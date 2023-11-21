package srsc.fserver.services;

import org.springframework.stereotype.Service;

@Service
public class StorageService {

    public String listPath(String path) {
        // TODO (criar ligação com websockets)
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
