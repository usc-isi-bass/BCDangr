# this module is for bcd modularization evaluation
import random

class Evaluate_Community:

    def __init__(self, bcd_community, community_grandthrough):
        self.comminuties = bcd_community
        self.grandthrough = community_grandthrough
        self.extracted_cu_community = self.evaluate_commmunities()
        self.average_score_community = self.compute_average_score_bcd_community()
    
    def evaluate_commmunities(self):

        community_funcgroup = {}
        counter = 0
        for com in self.comminuties:
            counter+=1
 
            count = 0
            com_group = {}
            for func_name , func_address in self.comminuties[com]:
                #print(func_name)
                temp_func = func_name
                if func_name in list(self.grandthrough.keys()):
                    #print(func_name)
                    if len(self.grandthrough[func_name]) == 1:
                        #print(self.grandthrough[func_name][0])
                        com_group[temp_func] = self.grandthrough[func_name][0]
                    else:
                        com_group[temp_func] = self.grandthrough[func_name]
                    count+=1
                else:
                    
                    func_name = func_name.replace("{", "")
                    func_name = func_name.replace("}","")
                    if '::' in func_name:
                        #print(func_name)
                        parts = func_name.split("::")
                        for part in parts:
                            if '(' in part:
                                func_name = part.split("(")[0]
                                func_name = func_name .split(" ")[0]
                                #print(func_name)
                                if func_name in list(self.grandthrough.keys()):
                                    
                                    count+=1
                                    if len(self.grandthrough[func_name]) == 1:
                                        #print("ok")
                                        
                                        com_group[temp_func] = self.grandthrough[func_name][0]
                                    else:
                                        entry_count = []
                                        for entry in self.grandthrough[func_name]:
                                            counter = 0
                                            for part in parts:
                                                if part in entry:
                                                    counter+=1
                                            
                                            entry_count.append((entry, counter))
                                        sorted_list = sorted(entry_count,key=lambda t: t[1])  
                                        cu = sorted_list[-1][0]
                                        #print("cu is here")
                                        com_group[temp_func] = cu 
                                        #print(cu)                                
                                        #print(cu_funcs[func_name])
                                else:
                                    #print(parts)
                                    class_parts = parts[0].split(" ")[-1].strip()
                                    #print("this is exception")
                                    #print(class_parts)
                                    com_group[temp_func] = [class_parts]
                                
            #print(count)
            community_funcgroup[com] = com_group
        return community_funcgroup
    
    
    def compute_score_community(self, community):
        #compute the score for a community
        number_instances, num = self.find_unique_instances(community)
        score = num - number_instances

        if num != 0:
            final_score = (score*100)/num
            return final_score
        return None 
    
    def compute_location_class(self):
        #compute where is the right place for each class
        pass
    
    def compute_location_module(self):
        #compute where is the right place for each module
        pass

    def find_unique_instances(self, value_lists):
        #find unique instances
        unique_instances = set()
        counter = 0
        for item in value_lists:
            if len(item)>1:
                if all(isinstance(x, list) for x in item):
                    random_el = random.choice(item)
                    counter+=1
                    unique_instances.add(random_el[-1])
                    
                elif all(isinstance(x, str) for x in item):
                    counter+=1
                    unique_instances.add(item[-1])
        
        return len(unique_instances), counter
    
    def compute_average_score_bcd_community(self):
            
        counter = 0
        sum_com = 0
        for c in self.extracted_cu_community:
            #print(c)

            com_values = list(self.extracted_cu_community[c].values())

            score_this_commitny = self.compute_score_community(com_values)
            #print(score_this_commitny)
            if score_this_commitny is not None:
                counter+=1
                sum_com = sum_com+score_this_commitny

        if counter != 0:
            return sum_com/counter
        
        return None
    def compute_cu_places(self, comes):
        #print(len(comes))
        com_locations = {}
        counter = 0
        for com in comes:
            counter+=1
            classes = []
            modules = []
            for item in comes[com]:
                result = comes[com][item]
                if isinstance(result[0], list):
                    result = result[0]
                if len(result) == 2:
                    modules.append(result[1])
                elif len(result) == 3:
                    #print(result[1])
                    classes.append(result[1])
                    modules.append(result[2])
                elif len(result) > 3:
                    modules.append(result[-1])
                    classes.append(result[-2])
                elif len(result) == 1:
                    #print("come here")
                    #print(result[0])
                    classes.append(result[0])

            com_locations[counter] = (classes, modules)
        return com_locations


    def compute_right_locations(self, classes_modules):
        classes_locations= {}
        modules_locations = {}
        classes_numbers = defaultdict(list)
        modules_numbers = defaultdict(list)
        
        for com in classes_modules:
            classes = classes_modules[com][0]
            modules = classes_modules[com][1]
            unique_classes = set(classes)
            unique_modules = set(modules)
            for clas in unique_classes:
                classes_numbers[clas].append((com,classes.count(clas)))
            
            for module in unique_modules:
                modules_numbers[module].append((com, modules.count(module)))

        for target in classes_numbers:
            list_tupe = classes_numbers[target]
            list_tupe.sort(key=lambda x: x[1])
            classes_locations[target] = list_tupe[-1][0]


        for part in modules_numbers:
            list_tupe2 = modules_numbers[part]
            list_tupe2.sort(key=lambda x: x[1])
            modules_locations[part] = list_tupe2[-1][0]
        
        return classes_locations, modules_locations


    def compute_proportional_score_for_colony(self, colony_number , colony, classes_loc, modules_loc):
        score_colony = 0 
        real_number = 0
        paths = []
        #print(len(colony))
        for path in colony:
            res = colony[path]
            if isinstance(res[0], list):
                res = res[0]
            if res[-1].endswith(".cpp"):
                directory = res[-1].split("/")[0]
                paths.append(directory)
            
        unique_directoris = list(set(paths))
        
        directories = []
        for direct in unique_directoris:
            directories.append((direct, paths.count(direct)))
        
        #print(directories)
        directories.sort(key=lambda x: x[1])
        main_directory = ""
        if len(directories):
            main_directory = directories[-1][0]
    
        for item in colony:
            #print(item)
            item_score  = 0              
            results = colony[item]
            #print(results)
            flag_one = False
            flag_two = False
            flag_three = False
            flag_four = False
            flag_five = False
            flag_six = False
            if isinstance(results[0], list):
                results = results[0]
            if results[-1].endswith(".cpp"):
                director = results[-1].split("/")[0]
                #print("director is here")
                #print(director)
                if director == main_directory:
                    #score_colony+=0.3
                    #item_score+=0.3
                    flag_one= True
                    #print("main directory is ok")

            if len(results) == 2:
                if flag_one:
                    score_colony+=0.4
                    item_score+=0.4

                #print("hereeeeeeeeeeeeeeeeeee is 2")
                location = modules_loc[results[-1]]
                #print(location)
                if location == colony_number:
                    score_colony += 0.6
                    item_score+= 0.6
                    flag_two = True

            if len(results) >= 3:
                #print("hereeeeeeeeeeeee is 3")
                #print(results)
                if flag_one:
                    score_colony+=0.4
                    item_score+=0.4


                location_class = classes_loc[results[-2]]
                #print(location_class)
                location_module = modules_loc[results[-1]]
                #print(location_module)
                #print(colony_number)
                if location_class == colony_number:
                    score_colony+=0.6
                    item_score+=0.6
                    flag_three = True
                '''if location_module == colony_number:
                    score_colony+=0.32
                    item_score+=0.32
                    flag_four = True'''
                #print(location_class)
                #print(location_module)
            if len(results) == 1:
                #print("results 0 is here")
                #print(results[0])
                location_class = classes_loc[results[0]]
                #print(location_class)
                if location_class == colony_number:
                    item_score+=1
                    score_colony+=1
                    flag_five = True


            if flag_one or flag_two or flag_three or flag_four or flag_five:
                real_number+=1
            #print(item_score)
            #print("******************************")
        return score_colony , real_number
