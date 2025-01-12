import pandas as pd
import numpy as np
import onnx
from sklearn.model_selection import train_test_split
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder, StandardScaler
from joblib import dump, load
import os


model_file = "incremental_model.joblib"

file_name = "ebpf_ml_model.h"


last_line = "#endif"

def build_c_file():
    if not os.path.exists(model_file):
        print("Module does not exist")
        return
    model = load(model_file)
    weight = model.coef_
    bias = model.intercept_
    source = "#ifndef EBPF_ML_MODEL\n"
    source+= "#define EBPF_ML_MODEL\n\n"
    source+= "const long double bias = "
    source+= str(bias[0])
    source+= ";\n\n"
    #print(np.size(weight,0))
    #print(np.size(weight,1))
    width =np.size(weight,0)
    height=np.size(weight,1)
    source += "const long unsigned ML_WIDTH  = "+str(width)+";\n"
    source += "const long unsigned ML_HEIGHT = "+str(height)+";\n\n"
    source+= "const long double weight["+str(width)+"]["+str(height)+"] = {\n"
    for i in weight:
        source+="\t"
        source+=str(set(i.tolist()))
        source+="\n"
    source+="};\n\n"
    source+=last_line
    #print(source)
    with open(file_name,"w") as e_file:
        e_file.write(source)


if __name__ == "__main__":
    build_c_file()
    #print("wieghts: ",model.coef_)
    #print("Bias: ",model.intercept_)
