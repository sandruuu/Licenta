
„SOLUȚIE SECURIZATĂ DE ACCES DISTANT LA RESURSE CU AUTENTIFICARE MULTIFACTOR”

DETALII

1.	PRECIZĂRI ŞI DATE INIŢIALE:
În contextul unui mediu digital globalizat, caracterizat de mobilitatea crescută a utilizatorilor și de accesul la resurse informatice distribuite geografic, securitatea conexiunilor la distanță a devenit o componentă esențială pentru funcționarea organizațiilor moderne. Asigurarea confidențialității, integrității și disponibilității datelor transmise prin intermediul acestor conexiuni reprezintă un obiectiv central al strategiilor de securitate cibernetică, în special în condițiile extinderii modelelor de lucru distribuit și a utilizării infrastructurilor informatice hibride.
Spațiul cibernetic, definit prin ansamblul sistemelor informatice, al rețelelor de comunicații și al fluxurilor de date asociate acestora, este strâns interconectat cu infrastructura fizică a organizațiilor. Această interdependență implică faptul că securizarea infrastructurilor critice presupune nu doar protecția componentelor hardware și a facilităților fizice, ci și implementarea unor mecanisme de securitate adecvate la nivelul canalelor de acces la distanță prin care sunt gestionate și utilizate resursele informatice.

Amplificarea atacurilor cibernetice, exploatarea credențialelor compromise, tentativele repetate de acces neautorizat și interceptarea traficului de rețea subliniază necesitatea adoptării unor mecanisme avansate de protecție. În acest context, soluțiile moderne de autentificare, control al accesului și monitorizare a sesiunilor utilizatorilor joacă un rol esențial în reducerea suprafeței de atac și în consolidarea nivelului general de securitate al conexiunilor la distanță.
Autentificarea multifactor (MFA) constituie una dintre cele mai eficiente abordări contemporane pentru consolidarea securității accesului la resurse informatice. Prin utilizarea combinată a cel puțin două categorii distincte de factori de autentificare — factori bazați pe cunoaștere (parole), factori bazați pe posesie (token-uri hardware sau aplicații de autentificare instalate pe dispozitive mobile) și factori biometrici — mecanismele MFA contribuie semnificativ la reducerea riscului de compromitere a conturilor, inclusiv în situațiile în care unul dintre factorii de autentificare este expus sau compromis.
În contextul evoluției amenințărilor cibernetice și al limitărilor inerente autentificării tradiționale bazate pe parolă, metodele moderne de autentificare la distanță se orientează tot mai mult către soluții de tip passwordless și utilizarea passkeys. În acest cadru, autentificarea multifactor evoluează de la un mecanism static de validare a identității către implementarea unor politici dinamice de control al accesului, bazate pe evaluarea riscului contextual, a stării de conformitate a dispozitivelor utilizate și a condițiilor în care este inițiată conexiunea. Aceste politici sunt integrate în modele avansate de securitate de tip conditional access, care permit adaptarea deciziilor de acces în funcție de nivelul de risc identificat.
Prezenta lucrare are ca obiectiv proiectarea și implementarea unei soluții tehnice pentru acces securizat la distanță la resurse informatice, prin integrarea mecanismelor de autentificare multifactor cu tehnologii moderne de comunicație criptată. Soluția propusă urmărește creșterea nivelului de securitate al sesiunilor de acces la distanță, precum și îmbunătățirea procesului de verificare și validare a identității utilizatorilor. În acest context, lucrarea își propune următoarele obiective specifice:
-	analiza infrastructurilor și a protocoalelor utilizate pentru realizarea accesului securizat la distanță;
-	studierea mecanismelor de autentificare multifactor și a modalităților de integrare a acestora în arhitecturi moderne de securitate;
-	proiectarea unei soluții care să permită conectarea securizată a utilizatorilor la resurse interne, prin aplicarea unor mecanisme suplimentare de verificare a identității;
-	implementarea unui sistem de analiză dinamică a parametrilor de autentificare, care să permită, în funcție de nivelul de risc și de gradul de conformitate al dispozitivelor, blocarea, restricționarea sau limitarea accesului la resurse;
-	testarea și evaluarea eficienței soluției propuse în scenarii relevante de acces la distanță, din perspectiva securității și a performanței.

2. MEMORIUL TEHNIC VA CONŢINE:
	A) Introducere 
	- context și motivația lucrării;
	- obiectivele lucrării;
	- structura pe capitole, etc.
	
	B) Noțiuni teoretice
	- prezentarea conceptelor fundamentale ale accesului la distanță, incluzând rețelele private virtuale (VPN), mecanismele de tunelare, protocoale de criptare și rolul controlului accesului în protejarea resurselor informatice;
	- descrierea principalelor modele de autentificare a utilizatorilor, respectiv autentificarea cu un singur factor, cu doi factori și autentificarea multifactor, din perspectiva securității accesului;
	- documentarea factorilor de autentificare în factori bazați pe cunoaștere, posesie și caracteristici biometrice;
	- analiza vulnerabilităților autentificării tradiționale bazate pe parole, în contextul amenințărilor cibernetice actuale;
	- prezentarea mecanismelor moderne de autentificare multifactor, incluzând OTP, HOTP/TOTP, autentificarea prin notificări push, token-urile hardware și autentificarea biometrică;
	- analiza tranziției către soluții de autentificare de tip passwordless și passkeys;
	- prezentarea conceptului de control al accesului (Conditional Access) bazat pe evaluarea dinamică a riscului contextual, a comportamentului utilizatorului și a conformității dispozitivelor;
	- descrierea principiilor modelului de securitate Zero Trust și a relației acestuia cu autentificarea multifactor și accesul securizat la distanță;
	- prezentarea tehnologiilor de securizare a comunicațiilor și a proceselor de autentificare, incluzând protocoale criptografice (TLS), certificate digitale și mecanisme de gestionare a identităților și credențialelor.
	
	
	C) Stadiul tehnic al aplicațiilor cu funcționalități similare existente și a soluțiilor care permit realizarea proiectului
	- prezentarea și analiza comparativă a soluțiilor comerciale și open-source care oferă funcționalități de acces securizat la distanță cu autentificare multifactor, precum Duo, Google Authenticator, Microsoft Authenticator, FreeOTP, etc. evidențiind capabilitățile, limitările și scenariile de utilizare ale acestora;
	- analiza protocoalelor de acces la distanță utilizate, incluzând OpenVPN, IPSec, SSH și RDP securizat, din perspectiva securității, performanței și integrării cu mecanismele moderne de autentificare;
	- prezentarea arhitecturilor moderne de acces securizat bazat pe identitate, cu accent pe modelele de tip Zero Trust Network Access (ZTNA) și diferențierea acestora față de abordările tradiționale bazate pe perimetru;
	- analiza mecanismelor de control al accesului condiționat (Conditional Access), incluzând evaluarea riscului contextual, conformitatea dispozitivelor, localizarea și comportamentul utilizatorilor, în cadrul soluțiilor existente;
	- descrierea rolului sistemelor de management al identităților și accesului (IAM) în integrarea MFA, politicilor dinamice de acces și a autentificării passwordless;
	- prezentarea tehnologiilor software și hardware necesare implementării unei soluții de acces securizat la distanță, incluzând servere de autentificare, componente de rețea, token-uri hardware, aplicații mobile și infrastructuri de chei publice;
	- definirea arhitecturii generale a soluției propusă și a fluxurilor operaționale de autentificare și autorizare, cu evidențierea etapelor de verificare a identității, evaluare a riscului și acordare sau restricționare a accesului la resurse.
	
	D) Crearea soluției tehnice
	- descrierea arhitecturii generale a soluției propusă pentru acces securizat la distanță, bazată pe autentificare multifactor și evaluare dinamică a riscului, evidențiind componentele principale și relațiile dintre acestea;
	- prezentarea componentelor funcționale ale soluției, incluzând modulul de autentificare, mecanismele de generare și validare a factorilor suplimentari de autentificare (TOTP, notificări push), serverul de autorizare și interfața de acces la resurse;
	- detalierea modului de integrare a factorilor multipli de autentificare, precum combinațiile parolă + TOTP, parolă + aplicație mobilă sau autentificare passwordless, în funcție de nivelul de risc asociat sesiunii;
	- descrierea mecanismelor de control al accesului (Conditional Access), incluzând evaluarea contextuală a autentificării pe baza parametrilor de risc, a conformității dispozitivelor și a politicilor de securitate definite;
	- prezentarea modului de gestionare a sesiunilor de acces, a criptării datelor și a protejării canalelor de comunicație, prin utilizarea protocoalelor criptografice și a mecanismelor de securizare a sesiunilor.
	
	E) Testare, concluzii și perspective de dezvoltare
	- prezentarea metodologiei de testare a soluției propuse, incluzând scenarii relevante de acces securizat la distanță, criterii de evaluare și parametri utilizați pentru analiza performanței, fiabilității și securității;
	- analiza rezultatelor obținute în urma testării soluției, cu evidențierea comportamentului sistemului în funcție de nivelul de risc, tipul de autentificare utilizat și conformitatea dispozitivelor;
	- sinteza principalelor rezultate și validarea obiectivelor inițiale ale lucrării, prin corelarea cerințelor de securitate cu soluția implementată;
	- evidențierea contribuțiilor personale, incluzând arhitectura propusă, mecanismele de autentificare multifactor integrate și implementarea politicilor dinamice de control al accesului;
	- analiza limitărilor soluției din punct de vedere tehnic și operațional, identificate în urma procesului de testare;
	- formularea direcțiilor viitoare de dezvoltare, incluzând extinderea sistemului cu noi metode de autentificare multifactor, integrarea cu platforme enterprise de management al identităților, optimizarea mecanismelor de evaluare a riscului și adaptarea soluției la arhitecturi avansate de tip Zero Trust.
	
	F) Bibliografie
	
G) Anexe (dacă e cazul)
- diagrame tehnice ale arhitecturii platformei;
- cod sursă relevant și exemple de implementare.

3.	LUCRĂRI GRAFICE DE ÎNTOCMIT:
	- realizarea diagramelor de arhitectură ale soluției propusă pentru acces securizat la distanță cu autentificare multifactor, evidențiind componentele funcționale și interacțiunile dintre acestea;
	- elaborarea schemelor bloc corespunzătoare procesului de autentificare multifactor, cu reprezentarea etapelor de verificare a identității și a deciziilor de control al accesului;
	- realizarea diagramelor de flux pentru stabilirea și gestionarea conexiunilor securizate, incluzând etapele de inițiere, autentificare, autorizare și acces la resurse;
	- documentarea și prezentarea codului sursă aferent componentelor software dezvoltate, în vederea susținerii implementării și evaluării soluției propuse.

4. BIBLIOGRAFIE:
- resurse online de specialitate privind autentificarea multifactor, protocoalele de acces securizat la distanță și managementul identităților digitale;
- cărți, articole științifice și publicații de specialitate dedicate securității comunicațiilor, criptografiei aplicate și modelelor moderne de acces la distanță;
- documentația oficială a platformelor, bibliotecilor și instrumentelor software utilizate pentru implementarea mecanismelor de autentificare multifactor;
- studii și lucrări academice care analizează eficiența autentificării multifactor în prevenirea accesului neautorizat și reducerea riscurilor de securitate.