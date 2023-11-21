package srsc.fserver.services;

import org.springframework.stereotype.Service;

@Service
public class AuthService {

    public String login(String username, String password) {
        // TODO (criar ligação com websockets)
        return "token";
    }

}
