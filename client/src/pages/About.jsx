import React from 'react'
import { FaEnvelope, FaLinkedin, FaGithub } from 'react-icons/fa'; 
import { TiMail , TiSocialLinkedin, TiSocialGithub } from 'react-icons/ti'; 

export default function About() {
  return (
    <div className='py-20 px-4 max-w-6xl mx-auto'>
      <h1 className='text-3xl font-bold mb-4 text-slate-800 '>About Urban Estate</h1>

      <p className='mb-4 text-slate-700'>Urban Estate is your go-to for living solutions. We focus on prime locations and smooth transactions to make finding your ideal urban home effortless.</p>

      <p className='mb-4 text-slate-700'>
      At Urban Estate, our mission is to empower you in navigating urban real estate confidently. We provide personalized guidance and deep market insights to help you achieve your real estate goals.
      </p>

      <p className='mb-4 text-slate-700'>We're more than just a real estate agency; we're your trusted partner. With our experienced team, we're dedicated to delivering outstanding service and making your experience with Urban Estate enjoyable and rewarding.</p>

      {/* Made by Section */}
      <div className="bg-gray-200 py-8">
        <div className="container mx-auto px-4">
          <h2 className="text-xl font-bold mb-2"><span className='font-semibold'> Made by : </span>   <span className='text-slate-700'>Shubham Yadav</span></h2>
          <div className="flex items-center space-x-4">
            
            <a target="_blank" href="https://www.linkedin.com/in/-shubham-yadav-/" className="text-gray-700 hover:text-gray-900 flex items-center">
              <TiSocialLinkedin className="w-6 h-6 mr-1" />
              LinkedIn
            </a>
            <a target="_blank" href="https://github.com/Shubh08am" className="text-gray-700 hover:text-gray-900 flex items-center">
              <TiSocialGithub className="w-6 h-6 mr-1" />
              GitHub
            </a>
            <a href="mailto:shubh08am@gmail.com" target="_blank" rel="noopener noreferrer" className="text-gray-700 hover:text-gray-900 flex items-center">
          <TiMail className="w-6 h-6 mr-1" />
           Mail
           </a>
          </div>
        </div>
      </div>
    </div>
  )
}