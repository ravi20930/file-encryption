require('dotenv').config();
const cors = require('cors');
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 3333;
const encryptedFilesDir = path.join(__dirname, 'encrypted-files');
const decryptedFilesDir = path.join(__dirname, 'decrypted-files');

// Create the required directories if they don't exist
fs.mkdirSync(encryptedFilesDir, { recursive: true });
fs.mkdirSync(decryptedFilesDir, { recursive: true });

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, encryptedFilesDir);
        },
        filename: (req, file, cb) => {
            const sanitizedFilename = file.originalname.replace(/\s/g, '_');
            cb(null, sanitizedFilename);
        }
    })
});
// Enable CORS for all routes
app.use(cors());
// Multiple File Upload API
app.post('/upload-multiple', upload.array('files'), (req, res) => {
    if (!req.files || req.files.length === 0) {
      res.status(400).send('No files uploaded');
      return;
    }
  
    // Get the encryption key from the environment variables
    const encryptionKey = process.env.ENCRYPTION_KEY;
  
    if (!encryptionKey) {
      res.status(500).send('Encryption key not found');
      return;
    }
  
    // Derive a 256-bit encryption key using SHA-256
    const derivedKey = crypto.createHash('sha256').update(encryptionKey).digest().slice(0, 32);
  
    // Process each uploaded file
    req.files.forEach((file) => {
      // Read the uploaded file into a buffer
      const uploadedFilePath = path.join(encryptedFilesDir, file.filename);
      const uploadedData = fs.readFileSync(uploadedFilePath);
  
      // Generate a random initialization vector (IV)
      const iv = crypto.randomBytes(16);
  
      // Create a cipher with the derived encryption key and IV
      const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
  
      // Create a write stream to the encrypted file
      const outputStream = fs.createWriteStream(uploadedFilePath);
  
      // Write the IV to the output stream as the first 16 bytes
      outputStream.write(iv);
  
      // Pipe the uploaded file data through the AES cipher to encrypt it and save to the encrypted file
      const encryptedStream = cipher.pipe(outputStream);
  
      encryptedStream.on('finish', () => {
        console.log(`File ${file.filename} uploaded and encrypted successfully`);
      });
  
      // Write the remaining uploaded data to the cipher stream
      cipher.write(uploadedData);
      cipher.end();
    });
  
    res.status(200).send('All files uploaded and encrypted successfully');
  });
  
// File Upload API
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        res.status(400).send('No file uploaded');
        return;
    }

    // Get the encryption key from the environment variables
    const encryptionKey = process.env.ENCRYPTION_KEY;

    if (!encryptionKey) {
        res.status(500).send('Encryption key not found');
        return;
    }

    // Derive a 256-bit encryption key using SHA-256
    const derivedKey = crypto.createHash('sha256').update(encryptionKey).digest().slice(0, 32);

    // Read the uploaded file into a buffer
    const uploadedFilePath = path.join(encryptedFilesDir, req.file.filename);
    const uploadedData = fs.readFileSync(uploadedFilePath);

    // Generate a random initialization vector (IV)
    const iv = crypto.randomBytes(16);

    // Create a cipher with the derived encryption key and IV
    const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);

    // Create a write stream to the encrypted file
    const outputStream = fs.createWriteStream(uploadedFilePath);

    // Write the IV to the output stream as the first 16 bytes
    outputStream.write(iv);

    // Pipe the uploaded file data through the AES cipher to encrypt it and save to the encrypted file
    const encryptedStream = cipher.pipe(outputStream);

    encryptedStream.on('finish', () => {
        res.status(200).send('File uploaded and encrypted successfully');
    });

    // Write the remaining uploaded data to the cipher stream
    cipher.write(uploadedData);
    cipher.end();
});

// File Download API
app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;

    const encryptedFilePath = path.join(encryptedFilesDir, filename);

    if (fs.existsSync(encryptedFilePath)) {
        // Get the encryption key from the environment variables
        const encryptionKey = process.env.ENCRYPTION_KEY;

        if (!encryptionKey) {
            res.status(500).send('Encryption key not found');
            return;
        }

        // Derive a 256-bit encryption key using SHA-256
        const derivedKey = crypto.createHash('sha256').update(encryptionKey).digest().slice(0, 32);

        // Read the encrypted file into a buffer
        const encryptedData = fs.readFileSync(encryptedFilePath);

        // Get the IV from the first 16 bytes of the encrypted data
        const iv = encryptedData.slice(0, 16);

        // Create a decipher with the derived encryption key and IV
        const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);

        // Create a write stream to the decrypted file
        const decryptedFilePath = path.join(decryptedFilesDir, filename);
        const decryptedStream = fs.createWriteStream(decryptedFilePath);

        // Pipe the encrypted data through the AES decipher to decrypt it and save to the decrypted file
        decipher.pipe(decryptedStream);

        // Write the remaining encrypted data to the decipher stream
        decipher.write(encryptedData.slice(16));
        decipher.end();

        // Listen for the finish event to send the response once the decryption is complete
        decryptedStream.on('finish', () => {
            res.sendStatus(200);
        });
    } else {
        res.status(404).send('File not found');
    }
});
app.delete('/delete', (req, res) => {
    // Delete all files in the decrypted files directory
    fs.readdirSync(decryptedFilesDir).forEach((file) => {
        const filePath = path.join(decryptedFilesDir, file);
        fs.unlinkSync(filePath);
    });

    res.status(200).send('All decrypted files deleted');
});

// Decrypt All Files API
app.post('/decrypt-all', (req, res) => {
    // Get the encryption key from the environment variables
    const encryptionKey = process.env.ENCRYPTION_KEY;

    if (!encryptionKey) {
        res.status(500).send('Encryption key not found');
        return;
    }

    // Derive a 256-bit encryption key using SHA-256
    const derivedKey = crypto.createHash('sha256').update(encryptionKey).digest().slice(0, 32);

    // Get the list of encrypted files
    const files = fs.readdirSync(encryptedFilesDir);

    // Decrypt each file
    files.forEach((file) => {
        // Read the encrypted file into a buffer
        const encryptedFilePath = path.join(encryptedFilesDir, file);
        const encryptedData = fs.readFileSync(encryptedFilePath);

        // Get the IV from the first 16 bytes of the encrypted data
        const iv = encryptedData.slice(0, 16);

        // Create a decipher with the derived encryption key and IV
        const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, iv);

        // Create a write stream to the decrypted file
        const decryptedFilePath = path.join(decryptedFilesDir, file.replace('.enc', ''));
        const decryptedStream = fs.createWriteStream(decryptedFilePath);

        // Pipe the encrypted data through the AES decipher to decrypt it and save to the decrypted file
        decipher.pipe(decryptedStream);

        // Write the remaining encrypted data to the decipher stream
        decipher.write(encryptedData.slice(16));
        decipher.end();
    });

    res.status(200).send('All files decrypted');
});

// Fetch All Decrypted Files API
app.get('/fetch-decrypted', (req, res) => {
    // Get the list of decrypted files
    const files = fs.readdirSync(decryptedFilesDir);

    res.status(200).json({ files });
});

// Fetch All Encrypted Files API
app.get('/fetch-encrypted', (req, res) => {
    // Get the list of encrypted files
    const files = fs.readdirSync(encryptedFilesDir);
  
    res.status(200).json({ files });
  });
  

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
