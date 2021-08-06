import com.idealista.fpe.FormatPreservingEncryption;
import com.idealista.fpe.config.Alphabet;

import java.util.LinkedHashMap;
import java.util.Set;

public class DecryptHelper {
    private static final String aTweak = "1867687968866456789";
    private Alphabet alphabet;

    public DecryptHelper(Alphabet alphabet,String inputToDecypt, String outputFileLocation) {
        this.alphabet=alphabet;

        FormatPreservingEncryption formatPreservingEncryption=FPEClassFromFile.createFPEObject(alphabet);

        StringBuilder nonSpecialCharacters = new StringBuilder();
        StringBuilder plain = new StringBuilder();

        if (FPEClassFromFile.containsSpecialCharacters(inputToDecypt)) {
            LinkedHashMap<Integer, Character> specialCharactersIndexesMap = new LinkedHashMap<>();
            char[] inputChars = inputToDecypt.toCharArray();

            for (int i = 0; i < inputChars.length; i++) {
                char c = inputChars[i];
                if (FPEClassFromFile.isSpecialCharacter(c)) {
                    specialCharactersIndexesMap.put(i, c);
                } else {
                    nonSpecialCharacters.append(String.valueOf(c));
                }
            }
            //decrypt the non special characters
            String encryptedNonSpecialCharacters = formatPreservingEncryption.decrypt(nonSpecialCharacters.toString(), aTweak.getBytes());
            plain.append(encryptedNonSpecialCharacters);

            //add the special characters back
            Set<Integer> keys = specialCharactersIndexesMap.keySet();
            for (Integer key : keys) {
                plain.insert(key, (Object) specialCharactersIndexesMap.get(key));
            }
        } else {
            plain.append(formatPreservingEncryption.decrypt(inputToDecypt, aTweak.getBytes()));
        }
        String plainText = plain.toString();
        FPEClassFromFile.writeToOutputFile(
//                "Value Entered: " + inputToDecypt + " -> Decrypted value: " +
                        plainText, outputFileLocation);
        System.out.println("Decryption Completed. Output in " + outputFileLocation);
    }
}
