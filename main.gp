/**
Copyright 2021 cryptoflop.org
Gestion des changements de mots de passe.
**/
randompwd(len) = {
  externstr(Str("base64 /dev/urandom | head -c ",len))[1];
}
dryrun=1;
sendmail(address,subject,message) = {
  cmd = strprintf("echo %d | mail -s '%s' %s",message,subject,address);
  if(dryrun,print(cmd),system(cmd));
}
chpasswd(user,pwd) = {
  cmd = strprintf("yes %s | passwd %s",pwd,user);
  if(dryrun,print(cmd),system(cmd));
}
template = {
  "Cher collaborateur, votre nouveau mot de passe est %s. "
  "Merci de votre comprehension, le service informatique.";
  }
change_password(user,modulus,e=7) = {
  iferr(
    pwd = randompwd(10);
    chpasswd(user, pwd);
    address = strprintf("%s@cryptoflop.org",user);
    mail = strprintf(template, pwd);
    m = fromdigits(Vec(Vecsmall(mail)),128);
    c = lift(Mod(m,modulus)^e);
    sendmail(address,"Nouveau mot de passe",c);
    print("[OK] changed password for user ",user);
  ,E,print("[ERROR] ",E));
}

/**************************************************************************************/

\\ le 128 vient de la fonction "change_password"
\\ on y voit que c'est l'entier choisi par le responsable informatique pour encoder
encode(m) = {
	  fromdigits(Vec(Vecsmall(m)),128);
	  }


decode(c) = {
	  Strchr(digits(c,128));
	  }

\\ on récupère la structure du message (copiée_collée du template,mais il doit y avoir une méthode parigp pour faire ce genre de chose...)
\\ et on la stocke dans un vecteur
get_struct()={
	debut = Vec(Vecsmall("Cher collaborateur, votre nouveau mot de passe est "));	
	fin = Vec(Vecsmall(". Merci de votre comprehension, le service informatique."));	
	\\ on n'oublie pas d'insérer un vecteur de longueur 10 pour le mdp
	\\ et conserver le nombre de caractères final.
	mdp=Vec(0,10);
	\\ on concatène pour récupérer une unique chaîne de caractères.
	chiffre=concat(debut,mdp);
	chiffre=concat(chiffre,fin);
	\\ on chiffre
	chiffre=encode(chiffre);
	\\ on renvoie le couple chiffré-(fin claire) (afin d'avoir la taille de la fin du message et de pouvoir replacer le mdp au bon endroit).
	return ([chiffre,fin]);
	}


\\ on utilise la méthode zncoppersmith
\\ Ici, on s'inspire fortement du deuxième exemple donné dans le manuel de parigp 
\\ à l'entrée zncoppersmith (qui présente justement une attaque sur RSA)
cp (n,e,message)={
	    [c,f]=get_struct();
	    padding=128^(#f)*unknown;
	    p = (c + padding)^e;
	    \\ pour choisir la borne, il faut regarder la taille du mdp
	    \\ on recherche une chaîne de longueur 10 caractères en base 128
	    borne = 128^10;
	    return (zncoppersmith(p - message,n,borne));
	    }



print_sol (mdp) = {
 	    print("Cher collaborateur, votre nouveau mot de passe est ",
 	    mdp, 
 	    ". Merci de votre comprehension, le service informatique.");
  	    }
  

text = readvec("input.txt");
n = text[1][1];
e = 7;
mail = text[2];
vec_cop= cp(n, e, mail);
\\ attention, la méthode zncoppersmith renvoie un vecteur d'entier !
\\ mais dans notre cas, il ne contient qu'une seule valeur.
sol=decode(vec_cop[1]);
print_sol(sol);









