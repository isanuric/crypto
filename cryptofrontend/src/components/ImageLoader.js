// import { React } from 'react';
import { Paper } from '@mui/material';
import * as React from 'react';

export default class LoadImages extends React.Component {

    constructor(props) {
        super(props);
        this.state={imageIndex: 0}
    }

    // Call setIntrvall AFTER render()
    componentDidMount() {
        this.intervalId = setInterval(() => {
            this.changeImage();
        }, this.props.interval);
    }

    changeImage() {
            this.setState((state, props) => {
                return {
                    imageIndex: getNextIndex(props.images, state.imageIndex)
                }
            });
    }

    componentWillUnmount() {
        clearInterval(this.intervalId)
    }

    render() {
        const currentImage = this.props.images[this.state.imageIndex];
        return (
            <Paper elevation={3}>
                <img src={currentImage.src} alt={currentImage.alt} width="1680" height="600"/>
            </Paper>
        );
    }
}

const getNextIndex = (images, currentIndex) => {
    if (currentIndex === images.length - 1) {
        return 0;
    }
    return currentIndex + 1;
}