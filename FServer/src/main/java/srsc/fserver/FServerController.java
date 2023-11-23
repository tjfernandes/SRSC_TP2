package srsc.fserver;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import srsc.fserver.services.AccessControlService;
import srsc.fserver.services.AuthService;
import srsc.fserver.services.StorageService;

@RestController
@RequestMapping("/api")
public class FServerController {

    private final AuthService authService;
    private final AccessControlService accessControlService;
    private final StorageService storageService;

    FServerController(AuthService authService,
                      AccessControlService accessControlService,
                      StorageService storageService) {
        this.authService = authService;
        this.accessControlService = accessControlService;
        this.storageService = storageService;
    }

    @GetMapping("/login")
    public ResponseEntity<String> loginUser(
            @RequestParam(name = "username") String username,
            @RequestParam(name = "password") String password
    ) {
        return ResponseEntity.ok(authService.login(username, password));
    }

    @GetMapping("/ls")
    public ResponseEntity<String> listUserPath(
            @RequestParam(name = "username") String username,
            @RequestParam(name = "path", defaultValue = "") String path
    ) {
       return ResponseEntity.ok(storageService.listPath(username, path));
    }

    @PostMapping("/mkdir")
    public ResponseEntity<Void> makeDirectory(
            @RequestParam(name = "username") String username,
            @RequestParam(name = "path") String path
    ) {
        storageService.makeDirectory(username, path);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/put")
    public ResponseEntity<Void> putFile(
            @RequestParam(name = "username") String username,
            @RequestParam(name = "file") String file
    ) {
        storageService.putFile(username, file);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("/get")
    public ResponseEntity<String> getFile(
            @RequestParam(name = "username") String username,
            @RequestParam(name = "file") String file
    ) {
        return ResponseEntity.ok(storageService.getFile(username, file));
    }

    @PutMapping("/cp")
    public ResponseEntity<Void> copyFile(
            @RequestParam(name = "username") String username,
            @RequestParam(name = "srcFile") String srcFile,
            @RequestParam(name = "destFile") String destFile
    ) {
        storageService.copyFile(username, srcFile, destFile);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @DeleteMapping("/rm")
    @PostMapping("/cp")
    public ResponseEntity<Void> copyFile(
            @RequestParam(name = "username") String username,
            @RequestParam(name = "file") String file
    ) {
        storageService.deleteFile(username, file);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("/file")
    public ResponseEntity<String> getFileDetails(
            @RequestParam(name = "file") String file
    ) {
        return ResponseEntity.ok(storageService.getFileDetails(file));
    }

}