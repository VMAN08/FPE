import com.idealista.fpe.FormatPreservingEncryption;
import com.idealista.fpe.builder.FormatPreservingEncryptionBuilder;
import com.idealista.fpe.config.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FPEClassFromFile {
    //    private static Alphabet alphabet;
    private static final String aTweak = "1867687968866456789";
    private static final char[] specialCharacters = {'@', '(', ')', ' ', '.', '*', '+', '-', '#', '[', ']', '|', '{', '}', ',', '/', '"', '"', ';', ':'};
    private static SecretKey secretKey;

    static {
        try {
            secretKey = generateKey(128);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    static String ssnPattern = "^(?!666|000|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0{4})\\d{4}$";
    static String phonePattern = "^(\\+\\d{1,2}\\s)?\\(?\\d{3}\\)?[\\s.-]\\d{3}[\\s.-]\\d{4}$";
    static String emailPattern = "^([\\w-\\.]+){1,64}@([\\w&&[^_]]+){2,255}.[a-z]{2,}$";
    static String lettersOnlyPattern = "^([a-zA-z/\\\\''(),\\-\\s]{2,255})$";
    static String numbersOnlyPattern = "\\d+";
    static String alphanumericsPattern = "^[a-zA-Z0-9]*$";

    static char[] numbersAlphabet = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    static char[] lettersOnlyAlphabet = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    static char[] alphanumericsAlphabet = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};


    //dynamically define alphabet to use based on user input
    public static Alphabet defineAlphabet(char[] alphabetChars) {
        Alphabet alphabet = new Alphabet() {

            private final char[] chars = alphabetChars;

            @Override
            public char[] availableCharacters() {
                return chars;
            }

            @Override
            public Integer radix() {
                return chars.length;
            }
        };
        return alphabet;

    }

    //create a FPE object passing in the alphabet defined above
    public static FormatPreservingEncryption createFPEObject(Alphabet alphabet) {
        //initialize the FPE Object
        return FormatPreservingEncryptionBuilder
                .ff1Implementation()
//define the Custom Domain (any subset of characters could be used)...could use the default domain but its alphabet only includes the lower case letters of the English alphabet
                .withDomain(new GenericDomain(alphabet, new GenericTransformations(alphabet.availableCharacters()), new GenericTransformations(alphabet.availableCharacters())))
//use default Pseudo Random Function to ensure that the same cipher function is persisted & always used; ensuring encryptions & decryptions match
//different PRFs won't return similar results
                .withDefaultPseudoRandomFunction(convertSecretKeyToByteArray(secretKey))
//The minimum length of input text
                .withLengthRange(new LengthRange(2, 100))
                .build();

    }

    //check input for occurrence of any of the special characters
    public static boolean containsSpecialCharacters(String inputString) {
        if (inputString == null) {
            return false;
        }
        Pattern regularCharacters = Pattern.compile("[^A-Za-z0-9]");
        Matcher matcher = regularCharacters.matcher(inputString);

        return matcher.find();
    }

    public static boolean isSpecialCharacter(char character) {
        List<Character> characters = new ArrayList<>();
        for (char c : specialCharacters) {
            characters.add(c);
        }
        return characters.contains(character);
    }

    public static void writeToOutputFile(String message, String outputFileLocation) {
        try {
            PrintWriter out = new PrintWriter(new FileWriter(outputFileLocation, true), true);
            out.write(message);
            out.write((System.getProperty("line.separator")));
            out.close();
        } catch (IOException e) {
            System.out.println(e);
            System.out.println("Cannot read file at \'" + outputFileLocation + "\'");
        }
    }

    private static void encryptHelper(String inputToEncrypt, String outputFileLocation, Alphabet alphabet) throws IOException {
        FormatPreservingEncryption formatPreservingEncryption = createFPEObject(alphabet);

        StringBuilder nonSpecialCharacters = new StringBuilder();
        StringBuilder cipher = new StringBuilder();

        if (containsSpecialCharacters(inputToEncrypt)) {
            LinkedHashMap<Integer, Character> specialCharactersIndexesMap = new LinkedHashMap<>();
            char[] inputChars = inputToEncrypt.toCharArray();

            for (int i = 0; i < inputChars.length; i++) {
                char c = inputChars[i];
                if (isSpecialCharacter(c)) {
                    specialCharactersIndexesMap.put(i, c);
                } else {
                    nonSpecialCharacters.append(String.valueOf(c));
                }
            }
            //encrypt the non special characters
            System.out.println("encrypting " + nonSpecialCharacters);
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
        writeToOutputFile("Value Entered: " + inputToEncrypt + " -> Encrypted value: " + cipherText, outputFileLocation);
        System.out.println("Encryption Completed. Output in " + outputFileLocation);
    }

    private static void decryptHelper(String inputToDecrypt, String outputFileLocation, Alphabet alphabet) throws IOException {
        FormatPreservingEncryption formatPreservingEncryption = createFPEObject(alphabet);

        StringBuilder nonSpecialCharacters = new StringBuilder();
        StringBuilder plain = new StringBuilder();

        if (containsSpecialCharacters(inputToDecrypt)) {
            LinkedHashMap<Integer, Character> specialCharactersIndexesMap = new LinkedHashMap<>();
            char[] inputChars = inputToDecrypt.toCharArray();

            for (int i = 0; i < inputChars.length; i++) {
                char c = inputChars[i];
                if (isSpecialCharacter(c)) {
                    specialCharactersIndexesMap.put(i, c);
                } else {
                    nonSpecialCharacters.append(c);
                }
            }
            //decrypt the non special characters
            String decryptedNonSpecialCharacters = formatPreservingEncryption.decrypt(nonSpecialCharacters.toString(), aTweak.getBytes());
            plain.append(decryptedNonSpecialCharacters);

            //add the special characters back
            Set<Integer> keys = specialCharactersIndexesMap.keySet();
            for (Integer key : keys) {
                plain.insert(key, (Object) specialCharactersIndexesMap.get(key));
            }
        } else {
            plain.append(formatPreservingEncryption.decrypt(inputToDecrypt, aTweak.getBytes()));
        }

        String plainText = plain.toString();
        writeToOutputFile("Value Entered: " + inputToDecrypt + " -> Encrypted value: " + plainText, outputFileLocation);
        System.out.println("Decryption Completed. Output in " + outputFileLocation);


    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter '1' to encrypt your input or '2' to decrypt your input");

        try {
            int userOption = scanner.nextInt();
            System.out.println("Enter Input File Location");
            scanner.nextLine();
            String inputFileLocation = scanner.nextLine();

            System.out.println("Enter Output File Location");
            String outputFileLocation = scanner.nextLine();

            String input;

            MyFileReader myFileReader = new MyFileReader(inputFileLocation);

            while (!myFileReader.endOfFile()) {
                input = myFileReader.readString();

                Alphabet alphabet;
                if (input.matches(ssnPattern)) {
                    System.out.println("ssn");
                    alphabet = defineAlphabet(numbersAlphabet);
                } else if (input.matches(phonePattern)) {
                    System.out.println("phone");
                    alphabet = defineAlphabet(numbersAlphabet);
                } else if (input.matches(lettersOnlyPattern)) {
                    System.out.println("letters only");
                    alphabet = defineAlphabet(lettersOnlyAlphabet);
                } else if (input.matches(numbersOnlyPattern)) {
                    System.out.println("numbers only");
                    alphabet = defineAlphabet(numbersAlphabet);
                } else if (input.matches(emailPattern)) {
                    System.out.println("email");
                    alphabet = defineAlphabet(lettersOnlyAlphabet);
                } else if (input.matches(alphanumericsPattern)) {
                    System.out.println("alphanumerics");
                    alphabet = defineAlphabet(alphanumericsAlphabet);
                } else {
                    alphabet = defineAlphabet(alphanumericsAlphabet);
                }
                if (userOption == 1) {
//                    encryptHelper(input, outputFileLocation, alphabet);
                    new EncryptHelper(alphabet,input, outputFileLocation);

                } else if (userOption == 2) {
//                    decryptHelper(input, outputFileLocation, alphabet);
                    new DecryptHelper(alphabet,input, outputFileLocation);
                }
            }
        } catch (InputMismatchException e) {
            System.out.println("Invalid output! Should be 1 or 2");
        } catch (IllegalArgumentException e) {
            System.out.println("Input out of range " + e);
        }
    }

    // method to generate secret key, takes an int argument that defines the length of the key
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        final String salt = "SaltSalt";
// use AES algorithm
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
// Generate a seed to aid in generating the encryption/decryption key
// A seed is a number (or vector) used to initialize a pseudorandom number generator.
// When a secret encryption/decryption key is pseudorandomly generated, having the seed will allow you to obtain the key
// If the same random seed is deliberately shared, it becomes a secret key,
// so two or more systems using matching pseudorandom number algorithms and matching seeds can generate matching sequences of non-repeating numbers
// this is how multiple runs of the program all generate the same key hence the consistency.
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.setSeed(salt.getBytes("UTF-8"));
//generate the key
        keyGenerator.init(n, secureRandom);

        return keyGenerator.generateKey();
    }

    //convert the secret key to get its value in a byte array to pass to the PRF Builder
    public static byte[] convertSecretKeyToByteArray(SecretKey secretKey) {

        return secretKey.getEncoded();
    }


}
