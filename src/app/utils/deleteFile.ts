import fs from 'fs';

export const deleteFile = (filePath: string) => {
  // Delete the old file from the server
  if (filePath && fs.existsSync(filePath)) {
    fs.unlinkSync(filePath); // Deletes the file
  }
};
