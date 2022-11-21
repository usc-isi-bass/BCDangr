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
        for com in self.comminuties:
            count = 0
            com_group = {}
            for func_name , func_address in self.comminuties[com]:
                #print(func_name)
                temp_func = func_name
                if func_name in list(self.grandthrough.keys()):
                    #print(func_name)
                    if len(self.grandthrough[func_name]) == 1:
                        print(self.grandthrough[func_name][0])
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

                                        com_group[temp_func] = cu                                 
                                        #print(cu_funcs[func_name])
                                else:
                                    class_parts = func_name.split("::")
                                    com_group[temp_func] = class_parts
                                
            #print(count)
            community_funcgroup[com] = com_group
        return community_funcgroup
    

    def compute_score_community(self, community):
        #compute the score for a community
        number_instances, num = find_unique_instances(community)
        score = num - number_instances

        if num != 0:
            final_score = (score*100)/num
            return final_score
        return None 
    
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