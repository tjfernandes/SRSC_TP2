package srsc.fserver.services;

import com.fasterxml.jackson.annotation.JsonTypeId;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.messaging.simp.stomp.StompHeaders;
import org.springframework.messaging.simp.stomp.StompSession;
import org.springframework.messaging.simp.stomp.StompSessionHandler;
import org.springframework.messaging.simp.stomp.StompSessionHandlerAdapter;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.messaging.WebSocketStompClient;

import java.lang.reflect.Type;
import java.util.concurrent.ExecutionException;

@Component
public class WebSocketClientService {

    @Value("${websocket.fAuth.url}")
    private String fAuthUrl;

    @Value("${websocket.fAccessControl.url}")
    private String fAccessControlUrl;

    @Value("${websocket.fStorage.url}")
    private String fStorageUrl;

    private final WebSocketStompClient stompClient;


    public WebSocketClientService(WebSocketStompClient stompClient) {
        this.stompClient = stompClient;
    }

    public void connectToServer(String serverName, String command) throws ExecutionException, InterruptedException {
        String serverURL = determineURL(serverName) + "/ws/" + serverName;

        StompSessionHandler sessionHandler = new StompSessionHandlerAdapter() {
            @Override
            public void afterConnected(StompSession session, StompHeaders connectedHeaders) {
                session.send("/app" + serverName, command.getBytes());
            }
        };

        stompClient.connectAsync(serverURL, sessionHandler).get();
    }

    private String determineURL(String serverName) {
        switch (serverName) {
            case "fServerAuth" -> {
                return fAuthUrl;
            }
            case "fServerAccessControl" -> {
                return fAccessControlUrl;
            }
            case "fServerStorage" -> {
                return fStorageUrl;
            }
            default -> {
                return "";
            }
        }
    }
}
