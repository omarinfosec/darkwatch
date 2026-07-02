// DarkWatch dashboard color tokens.
//
// `brand`  — interactive/UI accent (focus rings, primary buttons, hover
//            states, selected tab indicators). Matches /assets/logo.svg.
// Status colors (emerald = OK, red = critical, amber = warn, cyan = tg)
// stay as Tailwind defaults so health-state semantics remain unambiguous.
module.exports = {
  content: ["./index.html", "./src/**/*.{js,jsx,html}"],
  theme: {
    extend: {
      colors: {
        brand: {
          300: "#7BB8FF",   // lighter — hover-emphasis text
          400: "#4A9EFF",   // canonical — matches logo accent stroke
          500: "#2D7FDB",   // darker — solid backgrounds
          600: "#1F6BC0",   // active press state
        },
      },
    },
  },
};
