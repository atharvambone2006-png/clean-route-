/**
 * Global error handling middleware
 * @param {Error} error - The error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const errorHandler = (error, req, res, next) => {
    console.error('Error:', error.message);
    console.error('Stack:', error.stack);

    // Default error response
    let statusCode = error.statusCode || 500;
    let message = error.message || 'Internal Server Error';

    // Handle specific error types
    if (error instanceof SyntaxError) {
        statusCode = 400;
        message = 'Invalid JSON in request body';
    }

    if (error.name === 'ValidationError') {
        statusCode = 400;
        message = error.message;
    }

    res.status(statusCode).json({
        error: {
            status: statusCode,
            message: message,
            timestamp: new Date().toISOString()
        }
    });
};

export default errorHandler;
