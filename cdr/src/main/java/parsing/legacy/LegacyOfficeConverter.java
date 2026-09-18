package parsing.legacy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import security.sandbox.SubprocessSandbox;

/**
 * Shared hardened LibreOffice conversion boundary for legacy Office formats.
 * It never processes the untrusted legacy document in-process.
 */
public final class LegacyOfficeConverter {
    private static final String COMMAND_PROPERTY = "docshield.libreoffice.command";
    private static final String TIMEOUT_PROPERTY = "docshield.libreoffice.timeout.seconds";
    private static final String MAX_INPUT_PROPERTY = "docshield.libreoffice.max.input.bytes";
    private static final String MAX_OUTPUT_PROPERTY = "docshield.libreoffice.max.output.bytes";
    private static final long DEFAULT_TIMEOUT_SECONDS = 60;
    private static final long DEFAULT_MAX_INPUT_BYTES = 200L * 1024L * 1024L;
    private static final long DEFAULT_MAX_OUTPUT_BYTES = 200L * 1024L * 1024L;

    private LegacyOfficeConverter() { }

    public static Path convert(Path inputFile, String sourceLabel, String targetExtension) throws IOException {
        if (inputFile == null || !Files.exists(inputFile)) {
            throw new IOException(sourceLabel + " file does not exist.");
        }
        if (!Files.isRegularFile(inputFile) || !Files.isReadable(inputFile)) {
            throw new IOException(sourceLabel + " file is not a readable regular file.");
        }
        long inputSize = Files.size(inputFile);
        long maxInput = propertyLong(MAX_INPUT_PROPERTY, DEFAULT_MAX_INPUT_BYTES);
        if (inputSize > maxInput) {
            throw new IOException("LibreOffice conversion rejected: input " + sourceLabel
                    + " size " + inputSize + " bytes exceeds the conversion limit of " + maxInput + " bytes.");
        }

        Path workspace = Files.createTempDirectory("docshield_legacy_conversion_");
        Path outputDirectory = workspace.resolve("output");
        Path profileDirectory = workspace.resolve("profile");
        Files.createDirectories(outputDirectory);
        Files.createDirectories(profileDirectory);
        try {
            List<String> command = buildCommand(inputFile, outputDirectory, profileDirectory, targetExtension);
            long timeout = propertyLong(TIMEOUT_PROPERTY, DEFAULT_TIMEOUT_SECONDS);
            long maxOutput = propertyLong(MAX_OUTPUT_PROPERTY, DEFAULT_MAX_OUTPUT_BYTES);

            security.sandbox.SubprocessSandbox.SubprocessResult result =
                    security.sandbox.SubprocessSandbox.execute(
                            command,
                            workspace,
                            inputFile,
                            outputDirectory,
                            timeout,
                            maxOutput,
                            sourceLabel + " → " + targetExtension.toUpperCase() + " conversion timed out after " + timeout + " seconds.",
                            "LibreOffice " + sourceLabel + " conversion exceeded the output resource limit of " + maxOutput + " bytes."
                    );

            if (!result.isSuccess()) {
                throw new IOException("LibreOffice " + sourceLabel + " → " + targetExtension.toUpperCase()
                        + " conversion failed with exit code " + result.exitCode() + ". " + summarize(result.diagnostics()));
            }

            String original = inputFile.getFileName().toString();
            int dot = original.lastIndexOf('.');
            String stem = dot > 0 ? original.substring(0, dot) : original;
            Path converted = outputDirectory.resolve(stem + "." + targetExtension.toLowerCase());
            if (!Files.exists(converted)) {
                throw new IOException("LibreOffice reported successful " + sourceLabel + " conversion, but the converted "
                        + targetExtension.toUpperCase() + " was not found. " + summarize(result.diagnostics()));
            }
            if (!Files.isRegularFile(converted) || !Files.isReadable(converted)) {
                throw new IOException("LibreOffice produced a " + targetExtension.toUpperCase() + " that is not a readable regular file.");
            }
            long size = Files.size(converted);
            if (size == 0) throw new IOException("LibreOffice produced an empty " + targetExtension.toUpperCase() + " file.");
            if (size > maxOutput) throw new IOException("LibreOffice produced " + size + " bytes, exceeding the conversion output resource limit of " + maxOutput + " bytes.");
            return converted;
        } catch (InterruptedException e) {
            deleteWorkspace(workspace);
            Thread.currentThread().interrupt();
            throw new IOException("LibreOffice " + sourceLabel + " conversion was interrupted.", e);
        } catch (IOException | RuntimeException e) {
            deleteWorkspace(workspace);
            throw e;
        }
    }

    private static List<String> buildCommand(Path input, Path output, Path profile, String ext) {
        String command = System.getProperty(COMMAND_PROPERTY, "libreoffice");
        List<String> a = new ArrayList<>();
        a.add(command); a.add("--headless"); a.add("--nologo"); a.add("--nodefault");
        a.add("--norestore"); a.add("--nolockcheck");
        a.add("-env:UserInstallation=" + profile.toUri());
        a.add("--convert-to"); a.add(ext.toLowerCase()); a.add("--outdir");
        a.add(output.toAbsolutePath().toString()); a.add(input.toAbsolutePath().toString());
        return a;
    }
    private static String summarize(String s) {
        if (s==null || s.isBlank()) return "No LibreOffice diagnostic output was provided.";
        String n=s.replaceAll("\\s+"," ").trim(); return "LibreOffice: " + (n.length()>1000?n.substring(0,1000)+"...":n);
    }
    private static long propertyLong(String key,long def){String v=System.getProperty(key); if(v==null||v.isBlank())return def; try{long x=Long.parseLong(v);return x>0?x:def;}catch(NumberFormatException e){return def;}}
    private static void deleteWorkspace(Path workspace){ if(workspace==null||!Files.exists(workspace))return; try(var paths=Files.walk(workspace)){paths.sorted((a,b)->Integer.compare(b.getNameCount(),a.getNameCount())).forEach(p->{try{Files.deleteIfExists(p);}catch(IOException ignored){}});}catch(IOException ignored){} }
}
