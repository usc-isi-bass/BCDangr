import os 
import joblib

folder = 'ardupilot'

correct_components = {}

for dirpath, dirnames, filenames in os.walk(folder):
    #print(dirpath)
    coms = []
    for file_name in filenames:
        file_path = os.path.join(dirpath, file_name)
        if file_path.endswith('.c') or file_path.endswith('.cpp'):
            coms.append(file_name)
    if len(coms):
        correct_components[dirpath] = coms

joblib.dump(correct_components, 'correct_components.pkl')




