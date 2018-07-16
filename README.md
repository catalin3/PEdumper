# PEdumper

-Primeste in linia de comanda 3 parametrii, un prim parametru e un pattern de nume de fisiere(*.exe), 
al doilea parametru e optional, dar daca e prezent face ca acel pattern de nume de fisiere sa fie 
cautat in adancime in mod recursiv. Al treilea parametru poate fi "r" sau "R", daca este prezent operatiile 
se vor executa in mai multe threaduri.
    -Validam(campul e_magic) ca fisierul este executabil
    -Validam ca este executabil pe 32 biti
    -Daca trece validarea afisam cate un camp din ficare intrare din headere
    
-Afisarea in fisier a exporturilor si importurilor: (ex: fisierul nu are exporturi, sau ce exporta..)
(nume fctie si adresa)
