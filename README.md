# NetSentinel

## Commandes principales
```bash
mvn clean compile
java -cp target/classes com.netsentinel.Main clean
java -cp target/classes com.netsentinel.Main attack
mvn test -Dtest=NetSentinelSecurityTest
```

## Whitelist
- Fichier: src/main/resources/whitelist.txt
- Format: 1 IP par ligne
- Apres modification:
```bash
mvn -q -DskipTests compile && java -cp target/classes com.netsentinel.Main attack
```

Rapport créé: target/rapport_securite.txt
