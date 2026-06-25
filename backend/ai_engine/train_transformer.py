import os
import sys
import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, models, callbacks

# إضافة المجلد الحالي إلى sys.path لضمان استيراد preprocess بشكل سليم
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from preprocess import load_and_preprocess_data

# ----------------------------------------------------
# 1. طبقة الـ Positional Encoding (Sinusoidal)
# ----------------------------------------------------
class PositionalEncoding(layers.Layer):
    """
    طبقة الترميز الموضعي الجيبي (Sinusoidal Positional Encoding) 
    لإعطاء النموذج فكرة عن ترتيب أوامر الـ API Call زمنياً.
    """
    def __init__(self, sequence_length, embed_dim, **kwargs):
        super(PositionalEncoding, self).__init__(**kwargs)
        self.sequence_length = sequence_length
        self.embed_dim = embed_dim

    def build(self, input_shape):
        # حساب قيم الموضع والزوايا
        pos = np.arange(self.sequence_length)[:, np.newaxis]
        i = np.arange(self.embed_dim)[np.newaxis, :]
        angle_rates = 1 / np.power(10000, (2 * (i // 2)) / np.float32(self.embed_dim))
        angle_rads = pos * angle_rates
        
        # تطبيق الدوال الجيبية (sin للأعمدة الزوجية، cos للأعمدة الفردية)
        angle_rads[:, 0::2] = np.sin(angle_rads[:, 0::2])
        angle_rads[:, 1::2] = np.cos(angle_rads[:, 1::2])
        
        # تحويلها إلى Tensor ثابت وتوسيع الأبعاد لتناسب الـ Batch size
        self.pos_encoding = tf.constant(angle_rads[np.newaxis, ...], dtype=tf.float32)
        super(PositionalEncoding, self).build(input_shape)

    def call(self, inputs):
        # إضافة الترميز الموضعي لمخرجات طبقة الـ Embedding
        seq_len = tf.shape(inputs)[1]
        return inputs + self.pos_encoding[:, :seq_len, :]

    def get_config(self):
        config = super(PositionalEncoding, self).get_config()
        config.update({
            "sequence_length": self.sequence_length,
            "embed_dim": self.embed_dim,
        })
        return config

# ----------------------------------------------------
# 2. كتلة الـ Transformer Encoder Block
# ----------------------------------------------------
class TransformerEncoder(layers.Layer):
    """
    كتلة Transformer Encoder Block كاملة تحتوي على:
    - Multi-Head Self-Attention
    - Feed-Forward Neural Network
    - Layer Normalization و Residual Connections
    """
    def __init__(self, embed_dim, num_heads, ff_dim, dropout_rate=0.1, **kwargs):
        super(TransformerEncoder, self).__init__(**kwargs)
        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.ff_dim = ff_dim
        self.dropout_rate = dropout_rate
        
        # إنشاء المكونات الداخلية
        self.mha = layers.MultiHeadAttention(num_heads=num_heads, key_dim=embed_dim)
        self.ffn = tf.keras.Sequential([
            layers.Dense(ff_dim, activation="relu"),
            layers.Dense(embed_dim)
        ])
        
        self.layernorm1 = layers.LayerNormalization(epsilon=1e-6)
        self.layernorm2 = layers.LayerNormalization(epsilon=1e-6)
        
        self.dropout1 = layers.Dropout(dropout_rate)
        self.dropout2 = layers.Dropout(dropout_rate)

    def call(self, inputs, training=None):
        # 1. الـ Multi-Head Attention مع اتصال تخطي (Residual) والـ Normalization
        attn_output = self.mha(inputs, inputs, training=training)
        attn_output = self.dropout1(attn_output, training=training)
        out1 = self.layernorm1(inputs + attn_output)
        
        # 2. شبكة التغذية الأمامية (Feed Forward FFN) مع اتصال تخطي والـ Normalization
        ffn_output = self.ffn(out1, training=training)
        ffn_output = self.dropout2(ffn_output, training=training)
        return self.layernorm2(out1 + ffn_output)

    def get_config(self):
        config = super(TransformerEncoder, self).get_config()
        config.update({
            "embed_dim": self.embed_dim,
            "num_heads": self.num_heads,
            "ff_dim": self.ff_dim,
            "dropout_rate": self.dropout_rate,
        })
        return config

# ----------------------------------------------------
# 3. بناء هيكلية المودل (Model Architecture)
# ----------------------------------------------------
def build_transformer_model(vocab_size, max_len=100, embed_dim=64, num_heads=4, ff_dim=128, dense_units=64, dropout_rate=0.1):
    inputs = layers.Input(shape=(max_len,), name="input_api_sequences")
    
    # أ. طبقة الـ Embedding لتمثيل الـ APIs كفيكتورز
    x = layers.Embedding(input_dim=vocab_size, output_dim=embed_dim, mask_zero=True, name="api_embedding")(inputs)
    
    # ب. طبقة الترميز الموضعي (Positional Encoding)
    x = PositionalEncoding(sequence_length=max_len, embed_dim=embed_dim, name="positional_encoding")(x)
    
    # ج. طبقة الـ Transformer Encoder Block
    x = TransformerEncoder(embed_dim=embed_dim, num_heads=num_heads, ff_dim=ff_dim, dropout_rate=dropout_rate, name="transformer_encoder")(x)
    
    # د. التجميع العالمي للمتوسط (Global Average Pooling)
    x = layers.GlobalAveragePooling1D(name="global_average_pooling")(x)
    
    # هـ. الطبقات الكثيفة (Dense Layers) للتصنيف الثنائي
    x = layers.Dense(dense_units, activation="relu", name="dense_features")(x)
    x = layers.Dropout(dropout_rate, name="dropout_features")(x)
    outputs = layers.Dense(1, activation="sigmoid", name="output_classification")(x)
    
    model = models.Model(inputs=inputs, outputs=outputs, name="NeuroShield_Behavioral_Transformer")
    return model

# ----------------------------------------------------
# 4. دورة التدريب والتقييم الرئيسية
# ----------------------------------------------------
def main():
    print("🛡️ مرحباً بك في محرك تدريب NeuroShield Behavioral Transformer!")
    
    # تحديد مسارات الملفات
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, "dynamic_api_call_sequence_per_malware_100_0_306.csv")
    model_save_path = os.path.join(script_dir, "neuroshield_transformer.h5")
    
    # 1. تحميل وتجهيز البيانات
    if not os.path.exists(csv_path):
        print(f"❌ خطأ: لم يتم العثور على ملف البيانات في المسار {csv_path}")
        return
        
    X, y, tokenizer, vocab_size = load_and_preprocess_data(csv_path)
    
    # 2. تقسيم البيانات إلى تدريب واختبار (80% تدريب، 20% اختبار)
    print("✂️ جاري تقسيم البيانات...")
    np.random.seed(42)
    indices = np.arange(X.shape[0])
    np.random.shuffle(indices)
    
    split_idx = int(0.8 * len(indices))
    X_train, X_test = X[indices[:split_idx]], X[indices[split_idx:]]
    y_train, y_test = y[indices[:split_idx]], y[indices[split_idx:]]
    
    print(f"📈 عينات التدريب: {X_train.shape[0]} | عينات الاختبار: {X_test.shape[0]}")
    print(f"⚖️ توزيع الفئات في التدريب (0 سليم، 1 رانسوموير): {np.bincount(y_train)}")
    
    # 3. بناء وتجميع المودل
    print("🏗️ جاري بناء وتجميع المودل...")
    model = build_transformer_model(
        vocab_size=vocab_size,
        max_len=100,
        embed_dim=64,
        num_heads=4,
        ff_dim=128,
        dense_units=64,
        dropout_rate=0.1
    )
    
    model.summary()
    
    # تعريف المقاييس الهامة لكشف التهديدات السيبرانية
    metrics_list = [
        'accuracy',
        tf.keras.metrics.Precision(name='precision'),
        tf.keras.metrics.Recall(name='recall'),
        tf.keras.metrics.AUC(name='auc')
    ]
    
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss='binary_crossentropy',
        metrics=metrics_list
    )
    
    # 4. إعدادات الـ Callbacks لتدريب مرن ومنع الـ Overfitting
    early_stopping = callbacks.EarlyStopping(
        monitor='val_loss',
        patience=3,
        restore_best_weights=True,
        verbose=1
    )
    
    # 5. تدريب المودل
    print("🚀 جاري بدء التدريب...")
    history = model.fit(
        X_train, y_train,
        validation_split=0.15,
        epochs=12,
        batch_size=64,
        callbacks=[early_stopping],
        verbose=1
    )
    
    # 6. حفظ المودل بعد انتهاء الـ Epochs
    print(f"💾 جاري حفظ الموديل المدرب باسم neuroshield_transformer.h5...")
    model.save(model_save_path)
    print(f"✅ تم حفظ الموديل بنجاح في المسار: {model_save_path}")
    
    # 7. رسم وحفظ مخطط التدريب (إذا كانت matplotlib متوفرة)
    try:
        import matplotlib.pyplot as plt
        print("📊 جاري رسم منحنيات التدريب...")
        plt.figure(figsize=(12, 5))
        
        # Loss plot
        plt.subplot(1, 2, 1)
        plt.plot(history.history['loss'], label='Train Loss', color='#e74c3c', linewidth=2)
        plt.plot(history.history['val_loss'], label='Val Loss', color='#3498db', linewidth=2)
        plt.title('NeuroShield Loss History')
        plt.xlabel('Epochs')
        plt.ylabel('Loss')
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.6)
        
        # Accuracy plot
        plt.subplot(1, 2, 2)
        plt.plot(history.history['accuracy'], label='Train Acc', color='#2ecc71', linewidth=2)
        plt.plot(history.history['val_accuracy'], label='Val Acc', color='#f1c40f', linewidth=2)
        plt.title('NeuroShield Accuracy History')
        plt.xlabel('Epochs')
        plt.ylabel('Accuracy')
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.6)
        
        plt.tight_layout()
        plot_path = os.path.join(script_dir, "training_history.png")
        plt.savefig(plot_path)
        print(f"🖼️ تم حفظ رسم منحنى التدريب بنجاح: {plot_path}")
    except Exception as e:
        print(f"⚠️ تنبيه: لم يتم رسم المنحنيات لعدم توفر مكتبة matplotlib أو خطأ بالنظام: {e}")
        
    # 8. تقييم المودل على عينات الاختبار المستقلة
    print("🔍 جاري تقييم المودل النهائي على داتا الاختبار...")
    evaluation = model.evaluate(X_test, y_test, batch_size=64, verbose=0)
    
    eval_metrics = dict(zip(model.metrics_names, evaluation))
    print("\n================== 🔬 نتائج التقييم النهائي ==================")
    print(f"📉 Loss (خسارة الاختبار)  : {eval_metrics['loss']:.4f}")
    print(f"🎯 Accuracy (الدقة)        : {eval_metrics['accuracy'] * 100:.2f}%")
    print(f"🔵 Precision (الدقة العالية): {eval_metrics['precision'] * 100:.2f}%")
    print(f"🟢 Recall (القدرة على الاسترجاع): {eval_metrics['recall'] * 100:.2f}%")
    print(f"📈 AUC ROC (المساحة تحت المنحنى): {eval_metrics['auc']:.4f}")
    
    # حساب مقياس F1
    precision = eval_metrics['precision']
    recall = eval_metrics['recall']
    if (precision + recall) > 0:
        f1_score = 2 * (precision * recall) / (precision + recall)
        print(f"⚡ F1-Score (مقياس متوازن) : {f1_score * 100:.2f}%")
    print("=============================================================\n")
    
    print("ℹ️ لمعلوماتك: عند تحميل هذا الموديل برمجياً، استخدم الكود التالي:")
    print(">>> import tensorflow as tf")
    print(">>> from train_transformer import PositionalEncoding, TransformerEncoder")
    print(">>> model = tf.keras.models.load_model('neuroshield_transformer.h5',")
    print(">>>                                    custom_objects={'PositionalEncoding': PositionalEncoding,")
    print(">>>                                                    'TransformerEncoder': TransformerEncoder})")
    print("\n🏁 اكتملت العملية بنجاح!")

if __name__ == "__main__":
    main()
