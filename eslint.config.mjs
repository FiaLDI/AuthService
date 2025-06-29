import globals from "globals";
import jsConfig from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import prettier from "eslint-plugin-prettier"; // Import the Prettier plugin
import tsEslintPlugin from "@typescript-eslint/eslint-plugin"; // Import the TypeScript ESLint plugin
import stylisticJs from '@stylistic/eslint-plugin-js'

/** @type {import('eslint').Linter.FlatConfigArray} */
export default [
  {
    ignores: ["node_modules/", "build/", "**/*.config.js", "**/*.config.mjs"], // Игнорируемые файлы и папки
  },
  // Настройка для всех файлов
  {
    files: ["**/*.{js,mjs,cjs,ts}"],
    languageOptions: {
      parser: tsParser, // Используем TypeScript parser
      parserOptions: {
        ecmaVersion: "latest", // Поддержка последней версии ECMAScript
        sourceType: "module", // Модульный код
        ecmaFeatures: {
          jsx: true, // Включение поддержки JSX
        },
      },
      globals: globals.browser, // Глобальные переменные для браузера
    },
  },

  // Рекомендуемые правила JavaScript
  {
    rules: jsConfig.configs.recommended.rules,
  },
  // Рекомендуемые правила TypeScript
  {
    rules: tsPlugin.configs.recommended.rules,
  },
  {
    plugins: {
      prettier, // Указываем плагин Prettier в объекте
      "@typescript-eslint": tsEslintPlugin, // Указываем плагин TypeScript ESLint
      '@stylistic/js': stylisticJs
    },
    rules: {
      
      '@stylistic/js/indent': ['error', 4],
      '@stylistic/js/max-len': ['error', {
        "code": 80,
        "tabWidth": 4
      }],
      "react/react-in-jsx-scope": "off", // Отключаем правило для импорта React
      "@typescript-eslint/no-unused-vars": "warn", // Предупреждения для неиспользуемых переменных
      "prettier/prettier": [
        "error",
        {
          tabWidth: 4,
          useTabs: false
        }
      ] , 
        
    },
    
    settings: {
      react: {
        version: "detect", // Автоматическое определение версии React
      },
    },
  },
];
