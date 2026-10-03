package app.shizuku.smb;

// Runs inside the Shizuku user service process (shell or root uid).
interface IShareService {

    // Shizuku calls this transaction when the service is being removed.
    void destroy() = 16777114;

    // Returns the uid the service runs as (2000 = shell, 0 = root).
    int getUid() = 1;

    // Starts sharing. Returns null on success, otherwise a human-readable error.
    String start(String sharePath, String shareName, int port,
                 String username, String password, boolean readOnly) = 2;

    void stop() = 3;

    boolean isRunning() = 4;

    // Last status line from the service, for display in the UI.
    String getStatus() = 5;
}
