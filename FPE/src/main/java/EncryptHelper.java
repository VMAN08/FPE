import com.idealista.fpe.FormatPreservingEncryption;
import com.idealista.fpe.config.Alphabet;

import java.util.LinkedHashMap;
import java.util.Set;

public class EncryptHelper {
    private static final String aTweak = "1867687968866456789";
    private Alphabet alphabet;

    public EncryptHelper(Alphabet alphabet,String inputToEncrypt, String outputFileLocation) {
        this.alphabet=alphabet;

        FormatPreservingEncryption formatPreservingEncryption=FPEClassFromFile.createFPEObject(alphabet);

        StringBuilder nonSpecialCharacters = new StringBuilder();
        StringBuilder cipher = new StringBuilder();

        if (FPEClassFromFile.containsSpecialCharacters(inputToEncrypt)) {
            LinkedHashMap<Integer, Character> specialCharactersIndexesMap = new LinkedHashMap<>();
            char[] inputChars = inputToEncrypt.toCharArray();

            for (int i = 0; i < inputChars.length; i++) {
                char c = inputChars[i];
                if (FPEClassFromFile.isSpecialCharacter(c)) {
                    specialCharactersIndexesMap.put(i, c);
                } else {
                    nonSpecialCharacters.append(String.valueOf(c));
                }
            }
            //encrypt the non special characters
            String encryptedNonSpecialCharacters = formatPreservingEncryption.encrypt(nonSpecialCharacters.toString(), aTweak.getBytes());
            cipher.append(encryptedNonSpecialCharacters);

            //add the special characters back
            Set<Integer> keys = specialCharactersIndexesMap.keySet();
            for (Integer key : keys) {
                cipher.insert(key, (Object) specialCharactersIndexesMap.get(key));
            }
        } else {
            cipher.append(formatPreservingEncryption.encrypt(inputToEncrypt, aTweak.getBytes()));
        }
        String cipherText = cipher.toString();
        FPEClassFromFile.writeToOutputFile(
                cipherText, outputFileLocation);
        System.out.println("Encryption Completed. Output in " + outputFileLocation);
    }
}
