// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: "mern-estate-f969d.firebaseapp.com",
  projectId: "mern-estate-f969d",
  storageBucket: "mern-estate-f969d.appspot.com",
  messagingSenderId: "522166145933",
  appId: "1:522166145933:web:f211b0186604bed9cf63c4"
};

// Initialize Firebase
export const app = initializeApp(firebaseConfig);