from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import _tree
import pandas as pd
from sklearn.metrics import confusion_matrix
import numpy as np
import pickle
 
df = pd.read_csv("/home/netx2/Train_Model/Test/Tuesday-WorkingHours.pcap_ISCX.csv", usecols= ['Flow ID', ' Source IP', ' Source Port', ' Destination IP',
       ' Destination Port', ' Protocol', ' Flow Duration', 'Total Length of Fwd Packets', ' Flow IAT Min', ' Average Packet Size', ' SYN Flag Count', ' PSH Flag Count', ' ACK Flag Count', ' Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Active Mean', ' Active Min', ' Label'])
 
df[' Label'] = [1 if x != "BENIGN" else 0 for x in df[' Label']]
X= df[[' Flow Duration', 'Total Length of Fwd Packets', ' Flow IAT Min', ' Average Packet Size', ' SYN Flag Count', ' PSH Flag Count', ' ACK Flag Count', ' Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Active Mean', ' Active Min']].to_numpy()
y= df[[' Label']].to_numpy()
y = y.reshape(y.shape[0],).astype(int)
print(np.unique(y))
clf = DecisionTreeClassifier(max_depth = 4)
clf.fit(X, y)

y_pred = clf.predict(X)
tp = 0
tn = 0
fp = 0
fn = 0
for i in range(len(y)):
    if(y[i] == 1 and y_pred[i] == 1):
        tp+=1
    elif(y[i] == 1 and y_pred[i] == 0):
        fn+=1
    elif(y[i] == 0 and y_pred[i] == 1):
        fp+=1
    else:
        tn+=1
print(tp/(tp+fn))
print(tp/(tp+fp))
print((tp+tn)/(tp+fn+fp+tn))

def get_rules(tree, feature_names, class_names):
    tree_ = tree.tree_
    feature_name = [
        feature_names[i] if i != _tree.TREE_UNDEFINED else "undefined!"
        for i in tree_.feature
    ]

    paths = []
    path = []
    
    def recurse(node, path, paths):
        
        if tree_.feature[node] != _tree.TREE_UNDEFINED:
            name = feature_name[node]
            threshold = tree_.threshold[node]
            p1, p2 = list(path), list(path)
            p1 += [f"({name} <= {np.round(threshold, 3)})"]
            recurse(tree_.children_left[node], p1, paths)
            p2 += [f"({name} > {np.round(threshold, 3)})"]
            recurse(tree_.children_right[node], p2, paths)
        else:
            path += [(tree_.value[node], tree_.n_node_samples[node])]
            paths += [path]
            
    recurse(0, path, paths)

    # sort by samples count
    samples_count = [p[-1][1] for p in paths]
    ii = list(np.argsort(samples_count))
    paths = [paths[i] for i in reversed(ii)]
    
    rules = []
    for path in paths:
        rule = "if "
        
        for p in path[:-1]:
            if rule != "if ":
                rule += " and "
            rule += str(p)
        rule += " then "
        if class_names is None:
            rule += "response: "+str(np.round(path[-1][0][0][0],3))
        else:
            classes = path[-1][0][0]
            l = np.argmax(classes)
            rule += f"class: {class_names[l]} (proba: {np.round(100.0*classes[l]/np.sum(classes),2)}%)"
        rule += f" | based on {path[-1][1]:,} samples"
        rules += [rule]
        
    return rules

rules = get_rules(clf, [' Flow Duration', 'Total Length of Fwd Packets', ' Flow IAT Min', ' Average Packet Size', ' SYN Flag Count', ' PSH Flag Count', ' ACK Flag Count', ' Subflow Fwd Bytes', 'Init_Win_bytes_forward', 'Active Mean', ' Active Min'], [0,1])
for r in rules:
    print(r)

 
pickle.dump(clf, open('/home/netx2/DT.pkl', 'wb'))
 
# df_save = pd.read_csv("/home/c310/P4-Project/Traces/GeneratedLabelledFlows/TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv", usecols= ['Flow ID', ' Label'])
# df_save = df_save.drop_duplicates(subset = "Flow ID", keep = "first")
# df_save[' Label'] = [1 if x != "BENIGN" else 0 for x in df_save[' Label']]
 
# df_save.to_csv("/home/c310/P4-Project/save.csv")
 
 
 
 
 
 
