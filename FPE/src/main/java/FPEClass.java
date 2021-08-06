import com.idealista.fpe.FormatPreservingEncryption;
import com.idealista.fpe.builder.FormatPreservingEncryptionBuilder;
import com.idealista.fpe.component.functions.prf.DefaultPseudoRandomFunction;
import com.idealista.fpe.config.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.NumberFormat;
import java.text.ParsePosition;
import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.Scanner;
import java.util.regex.Pattern;

public class FPEClass {
    private static Alphabet alphabet;
    private static FormatPreservingEncryption formatPreservingEncryption;
    private static String aTweak = "1867687968866456789";
    private static SecretKey secretKey;

    static {
        try {
            secretKey = generateKey(128);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    static char[] digitsOnly = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    static char[] digitsPlusCommas = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', ','};
    static char[] lettersPlusDigits = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    static char[] lettersOnly = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
    static char[] lettersPlusSpecialCharacters = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', };
    static char[] ssnAlphabet = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    static char[] phoneAlphabet = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};


    //define regex to check for input containing numerals with commas. eg. 1,000
    private static Pattern pattern = Pattern.compile("\\d+(,\\d+)*(\\.\\d*)?");

    //use above pattern to check for input that matches the above pattern
    public static boolean isNumericWithCommas(String strNum) {
        if (strNum == null) {
            return false;
        }
        return pattern.matcher(strNum).matches();
    }

    //check for input that only contains numerals
    public static boolean isNumeric(String strNum) {
        if (strNum == null) {
            return false;
        }
        try {
            double d = Double.parseDouble(strNum);
        } catch (NumberFormatException nfe) {
            return false;
        }
        return true;
    }

    //dynamically define alphabet to use based on user input
    private static Alphabet defineAlphabet(char[] alphabetChars) {
        alphabet = new Alphabet() {

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
    private static void createFPEObject() {
        //initialize the FPE Object
        formatPreservingEncryption = FormatPreservingEncryptionBuilder
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
    private static boolean checkForSpecialCharacters(String inputString) {
        boolean containsSpecialCharacter =
                inputString.contains("@") ||
                        inputString.contains("(") ||
                        inputString.contains(")") ||
                        inputString.contains(".") ||
                        inputString.contains("+") ||
                        inputString.contains(" ") ||
                        inputString.contains("-");
//        System.out.println("checkForSpecialCharacters: found match? ->" + containsSpecialCharacter);
        return containsSpecialCharacter;
    }

    //for inputs found to contain special characters above, check which special character is contained
    public static String whichSpecialCharacter(String inputString) {
        if (inputString.contains("+")) {
            return "+";
        } else if (inputString.contains("(")) {
            return "(";
        } else if (inputString.contains(")")) {
            return ")";
        } else if (inputString.contains("@")) {
            return "@";
        } else if (inputString.contains(".")) {
            return ".";
        } else if (inputString.contains(" ")) {
            return " ";
        } else if (inputString.contains("-")) {
            return "-";
        }


        return "";
    }

    //helper method that takes in the input string to encrypt
    private static void encryptHelper(String inputToEncrypt) {
        //call method to create the FPE Object
        createFPEObject();

        /*define variables:
         * String Builder cipher to append the encrypted strings as well as the un-encrypted special chars
         * special char to hold the special chars to be appended
         * before and after strings hold the text before and after the special chars respectively*/
        StringBuilder cipher = new StringBuilder();
        String specialChar;
        String before, after;

        //check if the input contains any special characters
        if (checkForSpecialCharacters(inputToEncrypt)) {
            //check which special character is first
            specialChar = whichSpecialCharacter(inputToEncrypt);

            /*if the special character is at the start of the input eg: @gmail
             * populate the before variable*/
            if (inputToEncrypt.indexOf(specialChar) == 0) {
                before = specialChar;
                cipher.append(before);
//                System.out.println("appended " + before);
            } else {
                /*if the special character is not at the start, the before string holds
                 * all the non-special characters before the index of the special char,
                 * and after holds the non-special characters after the index of the special char
                 * eg: for user@gmail.com
                 * before holds:user
                 * specialchar holds: @
                 * after holds: gmail
                 */
                before = inputToEncrypt.substring(0, inputToEncrypt.indexOf(specialChar));
                try {
                    cipher.append(formatPreservingEncryption.encrypt(before, aTweak.getBytes()));
                    cipher.append(specialChar);

//                    System.out.println("appended " + specialChar);
                } catch (Exception e) {
                    System.out.println("Error: " + e);
                }

            }


            after = inputToEncrypt.substring(inputToEncrypt.indexOf(specialChar) + 1);

            /*if the after string also contains special characters which should be skipped during encryption,
             * the above criteria is applied whereby the variables are re-used and the 'after' string is now treated as the input
             * and is divided into a new 'before' and 'after' based on the position of the special char*/

            if (checkForSpecialCharacters(after)) {
                /*For all the occurrences of special chars in the 'after' substring,
                 * allocate values to special char, before and after
                 * this happens in a loop
                 *
                 * eg: user@company.co.ke
                 * loop 1:
                 * before: user
                 * specialchar: @
                 * after: company.co.ke
                 *
                 * loop 2:
                 * before: company
                 * specialchar: .
                 * after: co.ke
                 *
                 * loop 3:
                 * before: co
                 * specialchar: .
                 * after: ke
                 *
                 * end...
                 *
                 * the before and after strings are encrypted and appended in each loop and the special character is appended as well
                 * */
                while (checkForSpecialCharacters(after)) {
                    specialChar = whichSpecialCharacter(after);
                    if (after.indexOf(specialChar) == 0) {
                        before = specialChar;
                        cipher.append(specialChar);

                    } else {
                        before = after.substring(0, after.indexOf(specialChar));
                    }
                    after = after.substring(after.indexOf(specialChar) + 1);
//                    System.out.println(after);

                    try {
                        cipher.append(formatPreservingEncryption.encrypt(before, aTweak.getBytes()));
                        cipher.append(specialChar);

//                        System.out.println("appended " + before);
//                        System.out.println("appended " + specialChar);

                    } catch (Exception e) {

                    }
                }

            }
            cipher.append(formatPreservingEncryption.encrypt(after, aTweak.getBytes()));
//            System.out.println("appended " + after);
        } else {

            //if the input string has no special chars, it is encrypted as a whole
            cipher.append(formatPreservingEncryption.encrypt(inputToEncrypt, aTweak.getBytes()));
//            System.out.println("appended " + inputToEncrypt);
        }

        String cipherText = cipher.toString();
        System.out.println("You entered:" + inputToEncrypt);
        System.out.println("Encrypted value:" + cipherText);
    }

    /*this helper method uses similar logic to the encrypt helper, only decrypting where data was encrypted
    special characters are appended the same way to the plian stringbuilder variable
     */
    private static void decryptHelper(String inputToDecrypt) {
        createFPEObject();

        StringBuilder plain = new StringBuilder();
        String specialChar;
        String before, after;

        if (checkForSpecialCharacters(inputToDecrypt)) {
            specialChar = whichSpecialCharacter(inputToDecrypt);

            if (inputToDecrypt.indexOf(specialChar) == 0) {
                before = specialChar;
                plain.append(before);
            } else {
                before = inputToDecrypt.substring(0, inputToDecrypt.indexOf(specialChar));

                try {
                    plain.append(formatPreservingEncryption.decrypt(before, aTweak.getBytes()));

                    plain.append(specialChar);
                } catch (Exception e) {
                    System.out.println("Error: " + e);
                }
            }
            after = inputToDecrypt.substring(inputToDecrypt.indexOf(specialChar) + 1);

            if (checkForSpecialCharacters(after)) {
//                try {
//                    plain.append(formatPreservingEncryption.decrypt(before, aTweak.getBytes()));
//                } catch (Exception e) {
//                    System.out.println("Error " + e);
//                }
//                plain.append(specialChar);
                while (checkForSpecialCharacters(after)) {
                    specialChar = whichSpecialCharacter(after);
                    if (after.indexOf(specialChar) == 0) {
                        before = specialChar;
                        plain.append(specialChar);

                    } else {
                        before = after.substring(0, after.indexOf(specialChar));
                    }
                    after = after.substring(after.indexOf(specialChar) + 1);

                    try {
                        plain.append(formatPreservingEncryption.decrypt(before, aTweak.getBytes()));
                        plain.append(specialChar);
                    } catch (Exception e) {
                    }
                }
            }
            plain.append(formatPreservingEncryption.decrypt(after, aTweak.getBytes()));


        } else {
            plain.append(formatPreservingEncryption.decrypt(inputToDecrypt, aTweak.getBytes()));

        }
        String plainText = plain.toString();
        System.out.println("You entered: " + inputToDecrypt);
        System.out.println("Decrypted value: " + plainText);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        //define scanner
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter '1' to encrypt your input or '2' to decrypt your input");
        try {
            int userOption = scanner.nextInt();
            scanner.nextLine();
            //check if user wants to encrypt or decrypt
            /*
            for either of the options , there are 7 alternatives to check for the kind of input entered in order
            to determine a suitable alphabet
            An alphabet is defined dynamically based on the user input
            The defineAlphabet method is defined at the top of the class and takes in an array of character to be used in the particular library
             */
            if (userOption == 1) {
                System.out.println("Enter input to encrypt here: ");
                String inputToEncrypt = scanner.nextLine();
                if (isNumeric(inputToEncrypt)) {
                    System.out.println("1");
                    defineAlphabet(digitsOnly);
                } else if (inputToEncrypt.matches("^(\\+\\d{1,2}\\s)?\\(?\\d{3}\\)?[\\s.-]\\d{3}[\\s.-]\\d{4}$")) {
                    System.out.println("2");
                    defineAlphabet(phoneAlphabet);
                } else if (inputToEncrypt.matches("^(?!666|000|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0{4})\\d{4}$")) {
                    System.out.println("3");
                    defineAlphabet(ssnAlphabet);
                } else if (isNumericWithCommas(inputToEncrypt)) {
                    System.out.println("4");
                    defineAlphabet(digitsPlusCommas);
                } else if (inputToEncrypt.matches("^([A-Za-z])+$")) {
                    System.out.println("5");
                    defineAlphabet(lettersOnly);
                } else if (inputToEncrypt.matches("^[a-zA-Z0-9]*$")) {
                    System.out.println("6");
                    defineAlphabet(lettersPlusDigits);
                } else {
                    System.out.println("7");
                    defineAlphabet(lettersPlusSpecialCharacters);
                }

                encryptHelper(inputToEncrypt);

            } else if (userOption == 2) {
                System.out.println("Enter input to decrypt here: ");
                String inputToDecrypt = scanner.nextLine();
                if (isNumeric(inputToDecrypt)) {
                    System.out.println("1");
                    defineAlphabet(digitsOnly);
                } else if (inputToDecrypt.matches("^(\\+\\d{1,2}\\s)?\\(?\\d{3}\\)?[\\s.-]\\d{3}[\\s.-]\\d{4}$")) {
                    System.out.println("2");
                    defineAlphabet(phoneAlphabet);
                } else if (inputToDecrypt.matches("^(?!666|000|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0{4})\\d{4}$")) {
                    System.out.println("3");
                    defineAlphabet(ssnAlphabet);
                } else if (isNumericWithCommas(inputToDecrypt)) {
                    System.out.println("4");
                    defineAlphabet(digitsPlusCommas);
                } else if (inputToDecrypt.matches("^([A-Za-z])+$")) {
                    System.out.println("5");
                    defineAlphabet(lettersOnly);
                } else if (inputToDecrypt.matches("^[a-zA-Z0-9]*$")) {
                    System.out.println("6");
                    defineAlphabet(lettersPlusDigits);
                } else {
                    System.out.println("7");
                    defineAlphabet(lettersPlusSpecialCharacters);
                }
                decryptHelper(inputToDecrypt);

            } else {
                System.out.println("Incorrect Input, Must be '1' 0r '2'");
            }
        } catch (InputMismatchException e) {
            System.out.println("Invalid output! Should be 1 or 2");
        } catch (IllegalArgumentException e) {
            System.out.println("Input out of range " + e);
        }
    }

    //method to generate secret key, takes an int argument that defines the length of the key
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        final String salt = "SaltSalt";
//use AES algorithm
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//Generate a seed to aid in generating the encryption/decryption key
// A seed is a number (or vector) used to initialize a pseudorandom number generator.
// When a secret encryption/decryption key is pseudorandomly generated, having the seed will allow one to obtain the key
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
