package io.bumo.encryption.exception;

public class EncException extends RuntimeException{
	private static final long serialVersionUID = 429654902433634386L;
    private String message;
    
    public EncException(String message, Throwable cause) {
        super(message, cause);
        this.message = message;
    }

    public EncException(String message) {
        super(message);
        this.message = message;
    }

    public String getMessage() {
        return this.message;
    }
}
