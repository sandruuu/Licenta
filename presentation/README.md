# Prezentare licență

Prezentarea principală are 12 slide-uri și este calibrată pentru aproximativ 9 minute și 40 de secunde, cu 20 de secunde rezervă.

## Structură și timp recomandat

| Slide | Conținut | Timp |
|---:|---|---:|
| 1 | Copertă | 0:20 |
| 2 | Cuprins | 0:20 |
| 3 | Introducere | 0:40 |
| 4 | Relevanța și obiectivele lucrării | 0:50 |
| 5 | Arhitectura sistemului | 1:00 |
| 6 | Descrierea PDP | 1:10 |
| 7 | Descrierea aplicației locale | 1:10 |
| 8 | Descrierea Gateway | 1:10 |
| 9 | Rezultate: validare funcțională | 1:00 |
| 10 | Rezultate: performanță | 0:50 |
| 11 | Direcții viitoare | 0:45 |
| 12 | Concluzie și întrebări | 0:25 |

## Compilare

Din directorul `presentation`, rulează de două ori:

```powershell
xelatex -interaction=nonstopmode -halt-on-error -file-line-error prezentare_licenta.tex
```

Fișierul rezultat este `prezentare_licenta.pdf`.
