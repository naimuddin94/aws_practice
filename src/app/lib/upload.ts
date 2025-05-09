import multer from 'multer';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { AppError } from '../utils';
import status from 'http-status';
import fs from 'fs';

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let folderPath = './public';

    if (file.mimetype.startsWith('image')) {
      folderPath = './public/images';
    } else if (file.mimetype.startsWith('video')) {
      folderPath = './public/videos';
    } else {
      cb(
        new AppError(status.BAD_REQUEST, 'Only images and videos are allowed'),
        './public'
      );
      return;
    }

    // Check if the folder exists, if not, create it
    if (!fs.existsSync(folderPath)) {
      fs.mkdirSync(folderPath, { recursive: true });
    }

    cb(null, folderPath);
  },

  filename(_req, file, cb) {
    const fileExt = path.extname(file.originalname);
    const fileName = `${file.originalname
      .replace(fileExt, '')
      .toLocaleLowerCase()
      .split(' ')
      .join('-')}-${uuidv4()}`;

    cb(null, fileName + fileExt);
  },
});

const upload = multer({ storage });

export default upload;
