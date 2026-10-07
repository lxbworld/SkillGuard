# Each line is one acceptance case from issue #3.
rows = open('input.txt')            # read: no mode
with open('out.csv', 'w') as f:     # write: literal 'w'
    f.write('a,b\n')
data = open('data/x.csv', mode)     # unresolved mode: read, but noted
