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
    source+= "const float bias = "
    source+= str(bias[0])
    source+= ";\n\n"
    height=np.size(weight,0)
    width =np.size(weight,1)
    source += "const __u32 ML_WIDTH  = "+str(width)+";\n"
    source += "const __u32 ML_HEIGHT = "+str(height)+";\n\n"
    source += "const float weight["+str(height)+"]["+str(width)+"] = {\n"
    for i in weight:
        source+="\t"
        source+=str(set(i.tolist()))
        source+="\n"
    source+="};\n\n"
    source+=last_line
    #Other attributes that might not be needed.
    '''
    print("n_inter= "+str(model.n_iter_))
    print("classes= "+str(model.classes_))
    print("t_ up    "+str(model.t_))
    print("n featu  "+str(model.n_features_in_))
    '''

    #print(source)
    with open(file_name,"w") as e_file:
        e_file.write(source)


if __name__ == "__main__":
    build_c_file()
    #print("wieghts: ",model.coef_)
    #print("Bias: ",model.intercept_)
