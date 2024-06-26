from utils import *
from itertools import combinations
from encryption_test import test_encryption

### TRYING TO REWRITE RELAY_BOX ###
# Swap function
def swapPositions(list, pos1, pos2):
     
    list[pos1], list[pos2] = list[pos2], list[pos1]
    return list

def relay_box_2(input, control):
    output = list(input)
    if control[0] == '0':
        output = swapPositions(output,0,4)

    if control[1] == '0':
        output = swapPositions(output,3,4)

    if control[2] == '0':
        output = swapPositions(output,2,3)

    if control[3] == '0':
        output = swapPositions(output,1,2)

    if control[4] == '0':
        output = swapPositions(output,0,1)

    return output


# step 1: find positions of 00000 and 11111 groups

# initialize wheels with unknown bits
wheels = [['x']*period for period in periods]

weight_5_groups = []
weight_0_groups = []

# store positions of 0/5 weight groups
for i, ct in enumerate(ciphertext_encoded):
    if ct=='11111':
        weight_5_groups.append(i)
    if ct=='00000':
        weight_0_groups.append(i)

# construct five first bits at some times
board_1 = {}
for i in weight_5_groups:
    board_1[i] = XOR('11111', plaintext_encoded[i])
for i in weight_0_groups:
    board_1[i] = XOR('00000', plaintext_encoded[i])

# construct cabling for five first bits
impossible_cabling = {0: [], 1: [], 2: [], 3: [], 4: []}

# go through every period/wheel
for wheel, period in enumerate(periods):

    # go through every pair of the found first five bits
    for comb in combinations(board_1.keys(), 2):
        time_1, time_2 = comb

        # go through each position
        for b in range(5):
            # check if a pair has congruent time mod current wheel
            if (time_1%period)==(time_2%period):
                
                # check if the bit on position b is equal. If not, the cable from b <-> wheel is rejected
                if board_1.get(time_1)[b] != board_1.get(time_2)[b]:
                    if not (wheel in impossible_cabling.get(b)):
                        impossible_cabling[b].append(wheel)

# initialize empty cable list
cabling = ['x']*10

# go through the rejected cablings and store the possible combinations
for i_c in impossible_cabling.keys():
    for i in range(10):
        if i not in impossible_cabling.get(i_c):
            cabling[i_c] = i

# restore wheels with known cabling
for i in range(len(CIPHERTEXT)):
    for j, c in enumerate(cabling[:5]):
        if board_1.get(i):
            wheels[c][i%periods[c]] = board_1.get(i)[j]

# reconstruct some missing bits using some one/four weight bits
for i in range(len(CIPHERTEXT)):
    # plugboard at time i
    plugboard = ""

    for x in range(5):
        cable = cabling[x]
        plugboard += wheels[cable][i%periods[cable]]

    if plugboard.count('x') != 1:
        continue

    weight = ciphertext_encoded[i].count('1')
    if (weight != 1) and (weight != 4):
        continue

    unknown_pos = plugboard.index('x')
    missing_bit = find_missing(plugboard, plaintext_encoded[i], weight)  # using helper-function from utils.py

    for x in range(5):
        cable = cabling[x]
        if unknown_pos == x:
            wheels[cable][i%periods[cable]]=str(missing_bit)

# create the plugboard at every position
plugboard_1 = []
for i in range(len(CIPHERTEXT)):
    # plugboard at time i
    plugboard = ""
    for x in range(5):
        cable = cabling[x]
        plugboard += wheels[cable][i%periods[cable]]
    plugboard_1.append(plugboard)


# initialize empty dictionaries for weight 1 and 4 groups
weight_1_groups = {}
weight_4_groups = {}

control_bits_groups = {}
# find positions of weight 1 and 4 groups, aswell as possible control-bits for those positions
for i, c in enumerate(ciphertext_encoded):
    # plugboard at time i
    plugboard = plugboard_1[i]

    # create the relay-input for this position
    relay_input = XOR(plaintext_encoded[i], plugboard)

    # store positions of 1 weight groups
    if (c.count('1') == 1) and (relay_input.count('1') == 1):
        weight_1_groups[i] = c
        if df_weight_one[c][relay_input]:
            control_bits_groups[i] = df_weight_one[c][relay_input]

    # store positions of 4 weight groups
    if (c.count('0') == 1) and (relay_input.count('0') == 1):
        weight_4_groups[i] = c
        if df_weight_four[c][relay_input]:
            control_bits_groups[i] = df_weight_four[c][relay_input]

impossible_cabling_2 = {0: [], 1: [], 2: [], 3: [], 4: []}

# go through every wheel
for wheel, period in enumerate(periods):
    # skip if that cabling already exists
    if wheel in cabling:
       
        continue
    
    # go through every pair of control bits
    for comb in combinations(control_bits_groups.keys(), 2):
        time_1, time_2 = comb

        control_bits_t1 = control_bits_groups.get(time_1)
        control_bits_t2 = control_bits_groups.get(time_2)

        # skip if they are marked "false" in the table
        if (not control_bits_t1) or (not control_bits_t2):
            continue

        # go through every bit position
        for b in range(5):
            if (time_1%period) == (time_2%period):
                # skip check if one of the bits is unknown ('x') 
                if (control_bits_t1[b] == 'x') or (control_bits_t2[b] == 'x'):
                    continue

                # if bits are not equal, cable from b <-> wheel is impossible
                if control_bits_t1[b] != control_bits_t2[b]:
                    if not (wheel in impossible_cabling_2.get(b)):
                        impossible_cabling_2[b].append(wheel)

# restore wheels with known cabling
missing = [0,2,4,7,8]
for k in impossible_cabling_2.keys():
    for m in missing:
        if m not in impossible_cabling_2.get(k):
            cabling[5+k] = m
    
# reconstruct some bits for the last 5-bit group
for i in range(len(CIPHERTEXT)):
    for j,c in enumerate(cabling[5:]):
        if control_bits_groups.get(i):
            wheels[c][i%periods[c]] = control_bits_groups.get(i)[j]

# create the plugboard at every position
def update_plugboard_2():
    plugboard_2 = []
    for i in range(len(CIPHERTEXT)):
        # plugboard at time i
        plugboard = ""
        for x in range(5,10,1):
            cable = cabling[x]
            plugboard += wheels[cable][i%periods[cable]]
        plugboard_2.append(plugboard)
    return plugboard_2

plugboard_2 = update_plugboard_2()

# infer some missing bits by comparing control-bits directly from table, and the bits constructed from periodicity
for i, c in enumerate(ciphertext_encoded):
    # plugboard at time i
    plugboard = plugboard_1[i]

    # create the relay-input for this position
    relay_input = XOR(plaintext_encoded[i], plugboard)
    plugboard_test = None

    # store positions of 1 weight groups
    if (c.count('1') == 1) and (relay_input.count('1') == 1):
        plugboard_test = df_weight_one[c][relay_input]

    # store positions of 4 weight groups
    if (c.count('0') == 1) and (relay_input.count('0') == 1):
        plugboard_test = df_weight_four[c][relay_input]

    # infer some of the unknown values     
    if plugboard_test and plugboard_2[i]:
        if plugboard_2[i] != plugboard_test:
            updated_plugboard=""

            for b in range(5):
                if plugboard_2[i][b] != plugboard_test[b]:
                    if plugboard_2[i][b] == 'x' and plugboard_test[b] != 'x':
                        updated_plugboard += plugboard_test[b]
                    if plugboard_2[i][b] != 'x' and plugboard_test[b] == 'x':
                        updated_plugboard += plugboard_2[i][b]
                else:
                    updated_plugboard += plugboard_test[b]
            plugboard_2[i] = updated_plugboard


# update wheels after inferring some bits
for i in range(len(CIPHERTEXT)):
    for j,c in enumerate(cabling[5:]):
        bit = plugboard_2[i][j]
        if bit != wheels[c][i%periods[c]] and bit != 'x':

            wheels[c][i%periods[c]] = bit

plugboard_2 = update_plugboard_2()

# this asserts that five first wheels is correct with high probability
for i in range(len(CIPHERTEXT)):
    assert(XOR(plaintext_encoded[i],plugboard_1[i]).count('1') == ciphertext_encoded[i].count('1'))

### USE RELAY-BOX TO RECONSTRUCT LAST BITS###
replacement = {}
counter = 0
for i in range(len(CIPHERTEXT)):
    plugboard = plugboard_1[i]
    relay_input = XOR(plaintext_encoded[i], plugboard)
    relay_control = plugboard_2[i]
    
    # check what is the output from the relay box with current control bits
    relay_check = ''.join([relay_box_2(list(relay_input), list(relay_control))[x] for x in range(5)])

    # if the output is different from the ciphertext at that position, a bit needs to change
    if relay_check != ciphertext_encoded[i]:
        # look at cases where there's only one unknown bit
        if relay_control.count('x') == 1:

            # make a copy of the control bits where the unknown bit is set to 1 and 0, and test for both cases. Keep the correct case
            temp_1 = relay_control.replace("x","1")        
            temp_1_check = ''.join([relay_box_2(list(relay_input), list(temp_1))[x] for x in range(5)])
            if temp_1_check == ciphertext_encoded[i]:
                replacement[i] = temp_1

            temp_2 = relay_control.replace("x","0")
            temp_2_check = ''.join([relay_box_2(list(relay_input), list(temp_2))[x] for x in range(5)])
            if temp_2_check == ciphertext_encoded[i]:
                replacement[i] = temp_2

# update wheels with the new replacements
for pos, group in replacement.items():
    for i in range(5,10,1):
        cable = cabling[i]
        period = periods[cable]
        #if wheels[cable][pos%period] == 'x':
        wheels[cable][pos%period] = group[i-5]


plugboard_2 = update_plugboard_2()

# continue to reveal unknown bits by s
replacement = {}
for i in range(len(CIPHERTEXT)):
    plugboard = plugboard_1[i]
    relay_input = XOR(plaintext_encoded[i], plugboard)
    relay_control = plugboard_2[i]
    
    # check what is the output from the relay box with current control bits
    relay_check = ''.join([relay_box_2(list(relay_input), list(relay_control))[x] for x in range(5)])

    # only do cases where there's one unknown bit
    if relay_control.count('x') == 1:

        # make a copy of the control bits where the unknown bit is set to 1 and 0, and test for both cases. Keep the correct case
        temp_1 = relay_control.replace("x","1")        
        temp_1_check = ''.join([relay_box_2(list(relay_input), list(temp_1))[x] for x in range(5)])
        if temp_1_check == ciphertext_encoded[i]:
            replacement[i] = temp_1
            continue

        temp_2 = relay_control.replace("x","0")
        temp_2_check = ''.join([relay_box_2(list(relay_input), list(temp_2))[x] for x in range(5)])
        if temp_2_check == ciphertext_encoded[i]:
            replacement[i] = temp_2

# update wheels with the new replacements
for pos, group in replacement.items():
    for i in range(5,10,1):
        cable = cabling[i]
        period = periods[cable]
        #if wheels[cable][pos%period] == 'x':
        wheels[cable][pos%period] = group[i-5]

missing_bits = 0
for c in cabling:
    print(f"wheel {c}: {wheels[c]}")
    missing_bits += wheels[c].count('x')
print(f"Missing bits: {missing_bits}")

test_encryption(wheels, cabling)