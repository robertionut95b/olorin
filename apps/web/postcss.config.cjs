const tailwindcss = require('tailwindcss');
const autoprefixer = require('autoprefixer');

const config = {
  autoprefixer: {},
  plugins: [
    tailwindcss(),
    autoprefixer
  ]
};

module.exports = config;
