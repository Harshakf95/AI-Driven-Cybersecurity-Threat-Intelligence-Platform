// frontend/src/services/logger.js
class Logger {
    constructor(name) {
      this.name = name;
    }
  
    warn(message) {
      console.warn(`[${this.name}] ${message}`);
    }
  
    error(message, error) {
      console.error(`[${this.name}] ${message}`, error);
    }
  }
  
  export { Logger };