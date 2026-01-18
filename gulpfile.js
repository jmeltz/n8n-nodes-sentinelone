const { src, dest } = require('gulp');

function buildIcons() {
	return src('nodes/**/*.{svg,png,jpg,jpeg}').pipe(dest('dist/nodes'));
}

exports['build:icons'] = buildIcons;
