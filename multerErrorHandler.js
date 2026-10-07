// Multer-specific error middleware
// Ensures multipart errors return useful JSON instead of crashing.

const multerErrorHandler = (error, req, res, next) => {
  try {
    // Multer wraps its own errors as instances of Error with code like "LIMIT_FILE_SIZE" etc.
    const isMulter = Boolean(error && error.code && typeof error.code === 'string');

    if (!isMulter) return next(error);

    const code = error.code;

    // Map common Multer error codes to HTTP status + user friendly messages
    const map = {
      LIMIT_FILE_SIZE: {
        status: 413,
        message: 'One or more images are too large. Max size is 5MB per image.'
      },
      LIMIT_FILE_COUNT: {
        status: 400,
        message: 'Too many images. Max 5 photos allowed per report.'
      },
      LIMIT_UNEXPECTED_FILE: {
        status: 400,
        message: 'Unexpected file uploaded.'
      }
    };

    const mapped = map[code] || { status: 400, message: error.message || 'Upload failed.' };

    return res.status(mapped.status).json({
      error: {
        type: 'MULTER_UPLOAD_ERROR',
        code,
        message: mapped.message,
        timestamp: new Date().toISOString()
      }
    });
  } catch (e) {
    return next(e);
  }
};

export default multerErrorHandler;

