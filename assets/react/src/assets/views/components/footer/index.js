import React from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'

import ListBox from 'Components/listbox'

const Footer = (props) => {
    const Links = {
        headers: ["Company", "Learn", "Contact Us"],
        '0': [
            <a href='https://dapscoin.com/roadmap/' target="_blank">About</a>,
            <a href='https://dapscoin.com/team/' target="_blank">Team</a>,
            // <a href='google.com'>Careers</a>,
        ],
        "1": [
            <a href='https://dapscoin.com/roadmap/' target="_blank">Getting Started</a>,
            <a href='https://dapscoin.com/daps-project-blog/' target="_blank">DAPS Blog</a>,
            <a href='https://dapscoin.com/info/' target="_blank">What is DAPS?</a>,
        ],
        "2": [
            // <a href='google.com'>Press</a>,
            <a href='https://dapscoin.com/contact/' target="_blank">Support</a>,
            // <a href='google.com'>Status</a>,
        ],
        // "3": [<a href='google.com'>Local</a>],
    }
    const SocialLinks = {
        "headers": [],
        "0": [
            <a href='https://discord.gg/w898czA' id='discordlink' className='SocialLink' target="_blank" ><div id='discord' /></a>,
            <a href='https://www.facebook.com/dapscoinofficial/' id='facebooklink' className='SocialLink' target="_blank" ><div id='facebook' /></a>,
            <a href='https://www.reddit.com/r/DAPSCoin/' id='redditlink' className='SocialLink' target="_blank"><div id='reddit' /></a>,
            <a href='https://t.me/dapscoin' id='telegramlink' className='SocialLink' target="_blank" ><div id='telegram' /></a>,
            <a href='https://www.linkedin.com/company/daps-coin/' id='linkedinlink' className='SocialLink' target="_blank"><div id='linkedin' /></a>,
            <a href='https://twitter.com/DAPScoin' id='twitterlink' className='SocialLink' target="_blank" ><div id='twitter' /></a>,
        ]
    }



    return (<div className="Footer">
        <div id="FooterBar" />
        <div id="FooterInfo">
            <ListBox id="FooterLinks" data={Links}/>
            <div id="SocialLinksContainer">{SocialLinks[0]}</div>
            <div id="CR">
                <h2>Version: Beta</h2>
                <br />
                <h3>&copy; 2019 DAPScoin All Rights Reserved</h3>
            </div>
        </div>
    </div>
    )
};

//Footer.proptypes = {  }

export default Footer;