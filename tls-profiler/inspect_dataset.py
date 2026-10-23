import pandas as pd

df = pd.read_csv("dataset/train.csv")

print(df.head())
print(df.columns)
print(df.shape)
print(df["Label"].value_counts())