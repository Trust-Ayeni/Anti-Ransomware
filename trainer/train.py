import pandas as pd
import numpy as np
import pickle
import pefile
import sys
import array
import joblib
import math
import matplotlib.pyplot as plt


import seaborn as sns 


import sklearn.ensemble as ske
from sklearn.model_selection import train_test_split
from sklearn import tree, linear_model
from sklearn.feature_selection import SelectFromModel
import joblib
import xgboost as xgb
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
import os

import warnings
warnings.filterwarnings(action="ignore")


# Read data.csv file
data = pd.read_csv('data.csv', sep='|')
X = data.drop(['Name', 'md5', 'legitimate'], axis=1).values
y = data['legitimate'].values

print('Searching important feature based on %i total features\n' % X.shape[1])
data.head(10)
# Select most important features
fsel = ske.ExtraTreesClassifier(verbose=1,  n_estimators=2000, criterion='entropy').fit(X, y)
model = SelectFromModel(fsel, prefit=True, importance_getter="auto")
X_new = model.transform(X)
nb_features = X_new.shape[1]

# Split dataset into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X_new, y, test_size=0.30, train_size=0.70, random_state=5,  shuffle=True)


important_features = []

print(f"{nb_features} features identified as important:")

sorted_importances = np.argsort(fsel.feature_importances_)[::-1]
top_indices = sorted_importances[:nb_features]
for i, f in enumerate(top_indices):
    feature_name = data.columns[2 + f]
    feature_importance = fsel.feature_importances_[f]
    print(f"{i + 1}. feature {feature_name} ({feature_importance})")

sorted_top_indices = sorted(top_indices)
for f in sorted_top_indices:
    important_features.append(data.columns[2 + f])


# Train and evaluate machine learning algorithms
algorithms = {
    "DecisionTree": tree.DecisionTreeClassifier(max_depth=10),
    "RandomForest1": ske.RandomForestClassifier(n_estimators=150, max_features='log2'),
    "RandomForest2": ske.RandomForestClassifier(n_estimators=1000, max_features='log2'),
    "RandomForest3": ske.RandomForestClassifier(n_estimators=1500),
    "RandomForest4": ske.RandomForestClassifier(n_estimators=2000),
    "GradientBoosting": ske.GradientBoostingClassifier(n_estimators=50),
    "AdaBoost1": ske.AdaBoostClassifier(n_estimators=100, learning_rate=1.5),
    "AdaBoost2": ske.AdaBoostClassifier(n_estimators=300, learning_rate=1.5),
    "bdt_real": ske.AdaBoostClassifier(DecisionTreeClassifier(max_depth=4), n_estimators=350, learning_rate=1, algorithm="SAMME"),
    "bdt_discrete": ske.AdaBoostClassifier(DecisionTreeClassifier(max_depth=7), n_estimators=300, learning_rate=1.5, algorithm="SAMME"),
    "GNB": GaussianNB(),
    "KNN1": KNeighborsClassifier(n_neighbors=3, algorithm='auto'),
    "KNN2": KNeighborsClassifier(n_neighbors=2, algorithm='auto'),
    "XGBoost": xgb.XGBClassifier()
}
results = {}
for algo in algorithms:
    clf = algorithms[algo]
    clf.fit(X_train, y_train)
    score = clf.score(X_test, y_test)
    print("%s : %f %%" % (algo, score * 100))
    results[algo] = score

# Select the winning algorithm
winner = max(results, key=results.get)
print('\nWinner algorithm is %s with a %f %% success' %
      (winner, results[winner] * 100))

# Save the winning algorithm and selected features
joblib.dump(algorithms[winner], 'classifier/classifier.pkl')
open('classifier/features.pkl', 'wb').write(pickle.dumps(important_features))

# Calculate and print false positive and false negative rates
clf = algorithms[winner]
res = clf.predict(X_test)
mt = confusion_matrix(y_test, res)
print("False positive rate: %f %%" % ((mt[0][1] / float(sum(mt[0]))) * 100))
print("False negative rate: %f %%" % ((mt[1][0] / float(sum(mt[1])) * 100)))

result = {}
algorithm = {
    "SVM": SVC(kernel='rbf', gamma='auto', verbose=True)
}

# Train and test the SVM algorithm
classifier = algorithm["SVM"]
classifier.fit(X_train, y_train)
classifier_score = classifier.score(X_test, y_test)
print("SVM : %f %%" % (classifier_score * 100))
result["SVM"] = classifier_score

# Save the results of the SVM algorithm in a pickle file
joblib.dump(algorithm["SVM"], 'classifier/svm_classifier.pkl')
open('classifier/svm_features.pkl', 'wb').write(pickle.dumps(important_features))

# Calculate and print false positive and false negative rates
clfr = algorithm["SVM"]
reslt = clfr.predict(X_test)
mt1 = confusion_matrix(y_test, reslt)
print("False positive rate: %f %%" % ((mt1[0][1] / float(sum(mt1[0]))) * 100))
print("False negative rate: %f %%" % ((mt1[1][0] / float(sum(mt1[1])) * 100)))

import matplotlib.pyplot as plt

# Get the algorithm names and their scores
algorithm_names = list(results.keys())
scores = list(results.values())


plt.figure(figsize=(22,12))
plt.plot(algorithm_names, scores, color='blue', linestyle='dashed', marker='o', markerfacecolor='red', markersize=10)


# Add labels and title
plt.xlabel('Algorithm')
plt.ylabel('Score')
plt.title('Performance of different algorithms')

# Show the plot
plt.show()
