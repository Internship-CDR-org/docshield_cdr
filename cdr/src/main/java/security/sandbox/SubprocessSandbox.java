package security.sandbox;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Executes external subprocesses (such as LibreOffice fallback converters) inside an
 * isolated, resource-constrained sandbox jail to prevent exploits from compromising
 * the host system or network.
 */
public final class SubprocessSandbox {

    private static final int MAX_PROCESS_OUTPUT_BYTES = 64 * 1024;
    private static final boolean BWRAP_AVAILABLE = checkBwrapAvailable();

    private SubprocessSandbox() { }

    public record SubprocessResult(int exitCode, String diagnostics) {
        public boolean isSuccess() {
            return exitCode == 0;
        }
    }

    /**
     * Checks if Bubblewrap (bwrap) sandbox tool is present and functional on the system.
     */
    public static boolean isBwrapAvailable() {
        return BWRAP_AVAILABLE;
    }

    private static boolean checkBwrapAvailable() {
        String disableBwrap = System.getProperty("docshield.sandbox.bwrap.disable", "false");
        if ("true".equalsIgnoreCase(disableBwrap)) {
            return false;
        }
        try {
            Process process = new ProcessBuilder("bwrap", "--version")
                    .redirectErrorStream(true)
                    .start();
            boolean finished = process.waitFor(2, TimeUnit.SECONDS);
            if (finished && process.exitValue() == 0) {
                return true;
            }
            if (!finished) {
                process.destroyForcibly();
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Wraps a raw command line with Bubblewrap (bwrap) flags if bwrap is available on the system.
     * Enforces:
     * - --unshare-all (PID, IPC, UTS, user, network namespaces: complete airgap)
     * - --die-with-parent (kills container immediately if parent JVM terminates)
     * - Read-only root system mount (/ as read-only)
     * - Isolated writable workspace and scratch /tmp
     */
    public static List<String> buildSandboxedCommand(List<String> command, Path workspace, Path inputFile) {
        if (!BWRAP_AVAILABLE) {
            return new ArrayList<>(command);
        }

        List<String> sandboxed = new ArrayList<>();
        sandboxed.add("bwrap");
        sandboxed.add("--unshare-all");
        sandboxed.add("--die-with-parent");
        sandboxed.add("--new-session");

        // Read-only system root
        sandboxed.add("--ro-bind");
        sandboxed.add("/");
        sandboxed.add("/");

        // Proc and dev filesystems
        sandboxed.add("--proc");
        sandboxed.add("/proc");
        sandboxed.add("--dev");
        sandboxed.add("/dev");

        // Isolated temporary filesystem
        sandboxed.add("--tmpfs");
        sandboxed.add("/tmp");

        // If the command executable is an absolute path or script, ensure it is bound into sandbox
        if (command != null && !command.isEmpty()) {
            String exe = command.get(0);
            try {
                Path exePath = Path.of(exe);
                if (Files.exists(exePath)) {
                    sandboxed.add("--ro-bind-try");
                    sandboxed.add(exePath.toAbsolutePath().normalize().toString());
                    sandboxed.add(exePath.toAbsolutePath().normalize().toString());
                }
            } catch (Exception ignored) { }
        }

        // Read-only input file mount if specified
        if (inputFile != null && Files.exists(inputFile)) {
            sandboxed.add("--ro-bind-try");
            sandboxed.add(inputFile.toAbsolutePath().normalize().toString());
            sandboxed.add(inputFile.toAbsolutePath().normalize().toString());
        }

        // Writable isolated workspace
        if (workspace != null && Files.exists(workspace)) {
            sandboxed.add("--bind");
            sandboxed.add(workspace.toAbsolutePath().normalize().toString());
            sandboxed.add(workspace.toAbsolutePath().normalize().toString());
            sandboxed.add("--chdir");
            sandboxed.add(workspace.toAbsolutePath().normalize().toString());
        }

        // Target command and arguments
        sandboxed.addAll(command);
        return sandboxed;
    }

    /**
     * Executes a subprocess with comprehensive sandboxing, strict timeouts, output bounds,
     * and automatic process-tree destruction.
     */
    public static SubprocessResult execute(
            List<String> command,
            Path workspace,
            Path inputFile,
            Path monitoredOutputDirectory,
            long timeoutSeconds,
            long maxOutputBytes,
            String timeoutMessage,
            String limitMessage) throws IOException, InterruptedException {

        List<String> finalCommand = buildSandboxedCommand(command, workspace, inputFile);

        ProcessBuilder pb = new ProcessBuilder(finalCommand);
        if (workspace != null) {
            pb.directory(workspace.toFile());
        }
        pb.redirectErrorStream(true);

        Process process = pb.start();
        Process started = process;

        ExecutorService outputReader = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "docshield-sandbox-output");
            t.setDaemon(true);
            return t;
        });

        Future<String> outputFuture = outputReader.submit(() -> readBounded(started.getInputStream()));

        AtomicBoolean outputLimit = new AtomicBoolean(false);
        AtomicBoolean monitorFailure = new AtomicBoolean(false);
        ScheduledExecutorService monitor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "docshield-sandbox-monitor");
            t.setDaemon(true);
            return t;
        });

        ScheduledFuture<?> monitorTask = monitor.scheduleAtFixedRate(() -> {
            try {
                if (monitoredOutputDirectory != null && directorySize(monitoredOutputDirectory) > maxOutputBytes) {
                    outputLimit.set(true);
                    destroyProcessTree(started);
                }
            } catch (Exception e) {
                monitorFailure.set(true);
                destroyProcessTree(started);
            }
        }, 250, 250, TimeUnit.MILLISECONDS);

        boolean finished;
        try {
            finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            destroyProcessTree(process);
            throw e;
        } finally {
            monitorTask.cancel(true);
            monitor.shutdownNow();
        }

        if (!finished) {
            outputReader.shutdownNow();
            destroyProcessTree(process);
            throw new IOException(timeoutMessage);
        }

        if (outputLimit.get()) {
            outputReader.shutdownNow();
            throw new IOException(limitMessage);
        }

        if (monitorFailure.get()) {
            outputReader.shutdownNow();
            throw new IOException("Conversion could not be safely monitored for resource limits.");
        }

        String diagnostics;
        try {
            diagnostics = outputFuture.get(5, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            diagnostics = "Subprocess output could not be collected: " + e.getCause();
        } catch (TimeoutException e) {
            outputFuture.cancel(true);
            diagnostics = "Subprocess output collection timed out.";
        } finally {
            outputReader.shutdownNow();
        }

        return new SubprocessResult(process.exitValue(), diagnostics);
    }

    private static String readBounded(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0, n;
        while ((n = in.read(buf)) != -1) {
            int allowed = Math.min(n, MAX_PROCESS_OUTPUT_BYTES - total);
            if (allowed > 0) {
                b.write(buf, 0, allowed);
                total += allowed;
            }
        }
        return b.toString(StandardCharsets.UTF_8);
    }

    public static void destroyProcessTree(Process p) {
        if (p == null) return;
        try {
            p.toHandle().descendants().forEach(ProcessHandle::destroyForcibly);
            p.destroyForcibly();
            p.waitFor(5, TimeUnit.SECONDS);
        } catch (Exception ignored) { }
    }

    private static long directorySize(Path dir) throws IOException {
        if (!Files.exists(dir)) return 0;
        try (var paths = Files.walk(dir)) {
            long total = 0;
            for (Path p : (Iterable<Path>) paths::iterator) {
                if (Files.isRegularFile(p)) {
                    total = Math.addExact(total, Files.size(p));
                }
            }
            return total;
        }
    }
}
