/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'false',
  content: [
    '../templates/**/*.{html,js}',
    // './static/**/*.{html,js}',
  ],
  theme: {
    extend: {},
  },
  plugins: [
    require('@tailwindcss/forms'),
  ]
}