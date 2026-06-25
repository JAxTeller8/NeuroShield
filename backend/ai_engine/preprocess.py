import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import os

def load_and_preprocess_data(csv_path, max_sequence_len=100):
    print("🔄 جاري تحميل الداتا سيت لـ NeuroShield...")
    # 1. تحميل ملف الـ CSV
    df = pd.read_csv(csv_path)
    
    # التحقق من بنية الأعمدة لتحديد الطريقة المناسبة لقراءة البيانات
    if 'api_calls' in df.columns and 'label' in df.columns:
        X_text = df['api_calls'].astype(str).values
        y = df['label'].values
    elif 'malware' in df.columns:
        # كشف الأعمدة التي تبدأ بـ t_ (مثل t_0, t_1, ... t_99)
        t_cols = [col for col in df.columns if col.startswith('t_')]
        if len(t_cols) > 0:
            print(f"📊 تم اكتشاف {len(t_cols)} عمود تسلسلي (من t_0 إلى t_{len(t_cols)-1}).")
            # دمج قيم الأعمدة بمسافة بين كل قيمة لتشكيل متسلسلة نصية متوافقة مع الـ Tokenizer
            X_text = df[t_cols].astype(str).agg(' '.join, axis=1).values
        else:
            # في حال عدم وجود t_cols، نقوم بدمج كل الأعمدة عدا الأعمدة التعريفية
            print("⚠️ لم يتم العثور على أعمدة تبدأ بـ t_، سيتم دمج كل الأعمدة باستثناء المعرفات.")
            X_text = df.drop(columns=['hash', 'malware'], errors='ignore').astype(str).agg(' '.join, axis=1).values
        y = df['malware'].values
    else:
        raise KeyError("❌ خطأ: لم يتم العثور على الأعمدة المتوافقة مع الداتا سيت (api_calls/label أو t_x/malware).")
    
    print(f"📊 تم تحميل {len(df)} عينة بنجاح.")
    
    # 2. بناء الـ Tokenizer لـ "كلمات" الـ API Calls
    print("🧠 جاري تحضير الـ Tokenizer وتفكيك الـ API Calls...")
    tokenizer = Tokenizer(filters='', lower=True, oov_token='<OOV>')
    tokenizer.fit_on_texts(X_text)
    
    # تحويل النصوص إلى أرقام (Sequences)
    X_seq = tokenizer.texts_to_sequences(X_text)
    
    # 3. توحيد الطول (Padding) ليكون بالضبط 100 أمر متتالي لكل عملية
    X_padded = pad_sequences(X_seq, maxlen=max_sequence_len, padding='post', truncating='post')
    
    vocab_size = len(tokenizer.word_index) + 1
    print(f"✅ تم المعالجة بنجاح! حجم القاموس (Vocab Size): {vocab_size}")
    
    return X_padded, y, tokenizer, vocab_size

if __name__ == "__main__":
    # استخدام الملف المتوفر بالمجلد كافتراضي
    csv_filename = "dynamic_api_call_sequence_per_malware_100_0_306.csv" 
    
    if os.path.exists(csv_filename):
        X, y, tokenizer, vocab_size = load_and_preprocess_data(csv_filename)
        print("🚀 جاهزون لبناء طبقة الـ Behavioral Transformer Encoder!")
    else:
        # البحث في المجلد الأب أو المجلد الحالي
        script_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(script_dir, csv_filename)
        if os.path.exists(full_path):
            X, y, tokenizer, vocab_size = load_and_preprocess_data(full_path)
            print("🚀 جاهزون لبناء طبقة الـ Behavioral Transformer Encoder!")
        else:
            print(f"❌ خطأ: لم يتم العثور على ملف الـ CSV باسم {csv_filename} داخل المجلد.")