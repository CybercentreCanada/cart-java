# CaRT (Compressed and RC4 Transport)

The CaRT file format is used to store/transfer malware and its associated metadata.
It neuters the malware so it cannot be executed
and encrypts it so anti-virus software cannot flag the CaRT file as malware.

## Advantages

* FAST: CaRT is just as fast as zipping a file
* STREAMING: CaRT uses zlib and RC4 which allow it to encode files in streaming
* METADATA: CaRT can store the file metadata in the same file as the file itself, the metadata can be read without
  reading the full file
* HASH CALCULATION: CaRT calculates the hashes of the file while it is encoding it and store that information in the
  footer
* SIZE: CaRT files are usually smaller than the original files because it uses compression. (Except in the case when
  huge amounts of metadata are stored in the CaRT)

## Format Overview

### Mandatory Header (38 bytes)

CaRT has a mandatory header that looks like this

```
 4s     h         Q        16s         Q
CART<VERSION><RESERVED><ARC4KEY><OPT_HEADER_LEN>
```    

Where VERSION is 1 and RESERVED is 0. In most cases the RC4 key used to decrypt the file is stored in the mandatory
header and is always the same thing (first 8 digit of pi twice). However, CaRT provides an option to override the key
which then stores null bytes in the mandatory header. You'll then need to know the key to unCaRT the file...

### Optional Header (OPT_HEADER_LEN bytes)

CaRT's optional header is an OPT_HEADER_LEN bytes RC4 blob of a JSON serialized header

```
RC4(<JSON_SERIALIZED_OPTIONAL_HEADER>)
```

### Data block (N Bytes)

CaRT's data block is a zlib then RC4 block

```
RC4(ZLIB(block encoded stream))
```

### Optional Footer (OPTIONAL_FOOTER_LEN bytes)

Like the optional header, CaRT's optional footer is aN OPT_FOOTER_LEN bytes RC4 blob of a JSON serialized footer

```
RC4(<JSON_SERIALIZED_OPTIONAL_FOOTER>)
```

### Mandatory Footer (28 Bytes)

CaRT ends its file with a mandatory footer which allow the format to read the footer and return the hashes
without reading the whole file

```
 4s      QQ           Q
TRAC<RESERVED><OPT_FOOTER_LEN>
```

------------------------------------------------------------------------------------------------------------------

# CaRT (Compressed and RC4 Transport)

Le format de fichier CaRT permet de stocker et de transférer les maliciels et les métadonnées connexes.
Il neutralise les maliciels de manière à ce qu’ils puissent être exécutés et chiffrés pour que le logiciel antivirus ne
signale pas le fichier CaRT comme étant un maliciel.

## Avantages

* RAPIDE : Il est aussi rapide d’utiliser CaRT que de compresser un fichier.
* DIFFUSION EN CONTINU : CaRT utilise zlib et RC4, ce qui permet de coder les fichiers en cours de diffusion.
* MÉTADONNÉES : CaRT peut stocker les métadonnées d’un fichier dans le même fichier que le fichier lui-même;
  les métadonnées peuvent être lues sans qu'il soit nécessaire de lire le fichier en entier.
* CALCULS DE HACHAGE : CaRT calcule les condensés numériques du fichier parallèlement au codage du fichier, puis stocke
  l’information dans le pied de page.
* TAILLE : La taille des fichiers CaRT est généralement inférieure à celle des fichiers d’origine, puisqu’ils sont
  compressés (à moins qu’une grande quantité de métadonnées aient été stockées dans le CaRT).

## Aperçu du format

### En-tête obligatoire (38 octets)

CaRT comporte un en-tête obligatoire qui ressemble à ce qui suit :

```
 4s     h         Q        16s         Q
CART<VERSION><RESERVED><ARC4KEY><OPT_HEADER_LEN>
```

Dans cet en-tête, la valeur de VERSION est 1 et celle de RESERVED est 0. Dans la plupart des cas, la clé RC3 utilisée
pour déchiffrer le fichier y est stockée et elle est toujours la même (deux fois les 8 premiers chiffres
de la valeur pi). CaRT propose toutefois une façon de remplacer la clé, laquelle consiste à stocker des octets nuls
dans l’en-tête obligatoire. Vous devrez alors connaître la clé pour décoder le fichier CaRT.

### En-tête facultatif (OPT_HEADER_LEN octets)

L’en-tête facultatif de CaRT est un objet blob RC4 de OPT_HEADER_LEN octets tiré de l’en-tête sérialisé json

```
RC4(<JSON_SERIALIZED_OPTIONAL_HEADER>)
```

### Bloc de données (N octets)

Le bloc de données de CaRT est d’abord une bibliothèque logicielle de compression de données (zlib), puis un bloc RC4

```
RC4(ZLIB(block encoded stream))
```

### Pied de page facultatif (OPTIONAL_FOOTER_LEN octets)

Comme c’est le cas dans l’en-tête facultatif, le pied de page facultatif de CaRT est un objet blob RC4 de OPT_FOOTER_LEN
octets tiré de l’en-tête sérialisé json

```
RC4(<JSON_SERIALIZED_OPTIONAL_FOOTER>)
```

### Pied de page obligatoire (28 octets)

Le ficher CaRT se termine par un pied de page obligatoire qui permet au format de lire le pied de page et de renvoyer
les condensés numériques sans avoir à lire le fichier en entier :

```
 4s      QQ           Q
TRAC<RESERVED><OPT_FOOTER_LEN>
```