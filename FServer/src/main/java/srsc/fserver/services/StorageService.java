package srsc.fserver.services;

    import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import srsc.fserver.Servers;

import java.util.concurrent.ExecutionException;

@Service
public class StorageService {

    private final WebSocketClientService webSocketClientService;

    public StorageService(WebSocketClientService webSocketClientService) {
        this.webSocketClientService = webSocketClientService;
    }

    public String listPath(String username, String path) {
        try {
            webSocketClientService.connectToServer(Servers.F_SERVER_STORAGE.name(), String.format("ls %s %s", username, path));
        } catch (ExecutionException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        return "listed" + path;
    }

    public void makeDirectory(String username, String path) {
        // TODO (criar ligação com websockets)
    }

    public void putFile(String username, String file) {
        // TODO (criar ligação com websockets)
    }

    public String getFile(String username, String file) {
        return username+"/"+file;
    }

    public void copyFile(String username, String srcFile, String destFile) {
        // TODO (criar ligação com websockets)
    }

    public void deleteFile(String username, String file) {
        // TODO (criar ligação com websockets)
    }

    public String getFileDetails(String file) {
        return file;
    }


}
