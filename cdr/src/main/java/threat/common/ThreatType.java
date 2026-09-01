package threat.common;


/**
 * Universal categories used to classify security-relevant
 * content discovered during document inspection.
 *
 * These categories describe WHAT was found.
 * They do NOT automatically indicate that the content is malicious.
 *
 * Format-specific analyzers may use these categories while
 * storing more specific details in the evidence field.
 */
public enum ThreatType {

    /**
     * No specific category could be determined.
     */
    UNKNOWN,


    /**
     * An external reference or URI was found.
     */
    EXTERNAL_REFERENCE,


    /**
     * An external hyperlink was found.
     */
    EXTERNAL_HYPERLINK,


    /**
     * A generic embedded object was found.
     */
    EMBEDDED_OBJECT,


    /**
     * An OLE object was found.
     */
    OLE_OBJECT,


    /**
     * A VBA/macro project was found.
     */
    VBA_PROJECT,


    /**
     * An ActiveX object was found.
     */
    ACTIVEX_OBJECT,


    /**
     * A generic script-bearing resource was found.
     */
    SCRIPT_CONTENT,


    /**
     * A generic binary resource was found.
     */
    BINARY_RESOURCE,


    /**
     * An SVG resource was found.
     */
    SVG_RESOURCE,


    /**
     * A raster image resource was found.
     */
    IMAGE_RESOURCE,


    /**
     * An audio resource was found.
     */
    AUDIO_RESOURCE,


    /**
     * A video resource was found.
     */
    VIDEO_RESOURCE,


    /**
     * A suspicious XML construct was detected.
     */
    SUSPICIOUS_XML,


    /**
     * A suspicious archive/package structure was detected.
     */
    SUSPICIOUS_ARCHIVE,


    /**
     * A suspicious binary structure was detected.
     */
    SUSPICIOUS_BINARY,


    /**
     * A suspicious SVG construct was detected.
     */
    SUSPICIOUS_SVG,


    /**
     * A suspicious media construct was detected.
     */
    SUSPICIOUS_MEDIA,


    /**
     * A relationship points to a missing local package part.
     */
    MISSING_TARGET,


    /**
     * A relationship is structurally invalid.
     */
    INVALID_RELATIONSHIP,


    /**
     * Content was encountered that the current analyzer does
     * not understand or support.
     */
    UNSUPPORTED_CONTENT,


    /** Dynamic Data Exchange / DDE execution vector. */
    DDE,


    /** Excel 4.0 / XLM macro content. */
    XLM_MACRO,


    /** An embedded package/document that can carry active content. */
    EMBEDDED_PACKAGE,


    /** An executable native payload was found. */
    EXECUTABLE_PAYLOAD,


    /** A URI uses a dangerous application/file/script scheme. */
    DANGEROUS_URI,


    /** A document action can invoke an application, macro, or other active behavior. */
    DANGEROUS_ACTION,


    /** A remote/attached template is referenced. */
    EXTERNAL_TEMPLATE,

    /** Word is configured to update fields automatically when opened. */
    AUTO_UPDATE_FIELDS,


    /** A remotely fetched non-hyperlink resource is referenced. */
    EXTERNAL_RESOURCE,


    /** An external data/query/connection resource is referenced. */
    EXTERNAL_CONNECTION,

    /** A formula or workbook link references another workbook/data source. */
    EXTERNAL_WORKBOOK,

    /** A spreadsheet formula invokes a function capable of external/active access. */
    ACTIVE_FORMULA,


    /** XML contains a dangerous active/external construct. */
    MALICIOUS_XML,


    /** A package path attempts traversal outside its root. */
    PATH_TRAVERSAL,


    EMBEDDED_ACTIVE_CONTENT
}