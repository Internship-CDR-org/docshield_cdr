package identification;

public class FileInfo{
    private final String fileName;
    private final long fileSize;
    private final String extension;
    private final String mimeType;
    private final String sha256;
    private final Format format;
    private final boolean valid;
    private final boolean extensionMatch;

    public FileInfo(
            String fileName,
            long fileSize,
            String extension,
            String mimeType,
            String sha256,
            Format format,
            boolean valid,
            boolean extensionMatch) {

        this.fileName = fileName;
        this.fileSize = fileSize;
        this.extension = extension;
        this.mimeType = mimeType;
        this.sha256 = sha256;
        this.format = format;
        this.valid = valid;
        this.extensionMatch = extensionMatch;
    }

    public String getFileName() {
        return fileName;
    }

    public long getFileSize() {
        return fileSize;
    }

    public String getExtension() {
        return extension;
    }

    public String getMimeType() {
        return mimeType;
    }

    public String getSha256() {
        return sha256;
    }

    public Format getFormat() {
        return format;
    }

    public boolean isValid() {
        return valid;
    }

    public boolean isExtensionMatch() {
        return extensionMatch;
    }
}