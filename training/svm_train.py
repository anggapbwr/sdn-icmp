import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.svm import SVC
from sklearn.metrics import classification_report, accuracy_score
import joblib

# ========================
# 1. Load dataset
# ========================
normal = pd.read_csv("logs/traffic_normal.csv")
attack = pd.read_csv("logs/traffic_attack.csv")

# ========================
# 2. Tambah label
# ========================
normal["label"] = 0
attack["label"] = 1

# ========================
# 3. Gabungkan dataset
# ========================
df = pd.concat([normal, attack], ignore_index=True)

print("Total data:", len(df))

# ========================
# 4. Filter hanya ICMP (biar fokus)
# ========================
df = df[df["ip_proto"] == 1]

print("Setelah filter ICMP:", len(df))

# ========================
# 5. Drop kolom tidak penting
# ========================
df = df.drop(columns=[
    "timestamp",
    "src_mac",
    "dst_mac"
], errors="ignore")

# ========================
# 6. Handle missing value
# ========================
df = df.fillna(0)

# ========================
# 7. Encode categorical
# ========================
le_src = LabelEncoder()
le_dst = LabelEncoder()

df["src_ip"] = le_src.fit_transform(df["src_ip"].astype(str))
df["dst_ip"] = le_dst.fit_transform(df["dst_ip"].astype(str))

# ========================
# 8. Split fitur & label
# ========================
X = df.drop("label", axis=1)
y = df["label"]

# ========================
# 9. Train-test split
# ========================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42
)

# ========================
# 10. Train SVM
# ========================
model = SVC(kernel="rbf")

print("Training SVM...")
model.fit(X_train, y_train)

# ========================
# 11. Evaluasi
# ========================
y_pred = model.predict(X_test)

print("\n=== HASIL EVALUASI ===")
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# ========================
# 12. Simpan model
# ========================
joblib.dump(model, "svm_model.pkl")
print("\nModel disimpan sebagai svm_model.pkl")
