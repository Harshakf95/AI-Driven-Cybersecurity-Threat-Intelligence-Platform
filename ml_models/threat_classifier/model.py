import tensorflow as tf
from sklearn.model_selection import train_test_split
from typing import Tuple

class ThreatClassificationModel:
    def __init__(self, input_shape: Tuple[int, ...], num_classes: int):
        self.model = self._build_model(input_shape, num_classes)

    def _build_model(self, input_shape: Tuple[int, ...], num_classes: int) -> tf.keras.Model:
        """
        Build a neural network for threat classification
        """
        model = tf.keras.Sequential([
            tf.keras.layers.Input(shape=input_shape),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(num_classes, activation='softmax')
        ])
        
        model.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model

    def get_model(self):
        """
        Return the compiled model
        """
        return self.model