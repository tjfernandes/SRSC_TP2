package org.example.utils;

import java.util.concurrent.TimeoutException;

public class TimeoutUtils {
    public static void runWithTimeout(Runnable task, long timeoutMillis) throws TimeoutException {
        Thread t = new Thread(task);
        t.start();

        try {
            Thread.sleep(timeoutMillis);
            if (t.isAlive()) {
                t.interrupt();
                throw new TimeoutException("Connection take too long. Try again!");
            }
        } catch (InterruptedException ex) {
            ex.printStackTrace();
        }
    }
}