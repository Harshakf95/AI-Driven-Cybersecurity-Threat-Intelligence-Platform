import tensorflow as tf
import numpy as np
from model import ThreatClassificationModel

class ThreatModelTrainer:
    def __init__(self, input_shape: tuple, num_classes: int):
        self.model_cls = ThreatClassificationModel(input_shape, num_classes)
        self.model = self.model_cls.get_model()

    def prepare_data(self, X, y):
        """
        Prepare and preprocess training data
        """
        # Normalize data
        X = X / 255.0
        
        # One-hot encode labels
        y = tf.keras.utils.to_categorical(y, num_classes=self.model.layers[-1].units)
        
        return X, y

    def train(self, X_train, y_train, X_val, y_val, epochs: int = 50, batch_size: int = 32):
        """
        Train the threat classification model
        """
        X_train, y_train = self.prepare_data(X_train, y_train)
        X_val, y_val = self.prepare_data(X_val, y_val)

        # Early stopping and model checkpointing
        early_stopping = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss', 
            patience=10, 
            restore_best_weights=True
        )

        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[early_stopping]
        )

        return history

def main():
    # Example usage
    # Replace with actual data loading and preprocessing
    X_train = np.random.random((1000, 100))  # Example input features
    y_train = np.random.randint(0, 5, (1000,))  # Example labels
    X_val = np.random.random((200, 100))
    y_val = np.random.randint(0, 5, (200,))

    trainer = ThreatModelTrainer(input_shape=(100,), num_classes=5)
    history = trainer.train(X_train, y_train, X_val, y_val)

if __name__ == '__main__':
    main()