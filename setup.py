import setuptools

with open('README.md', 'r', encoding='utf-8') as readme_fh:
    long_description = readme_fh.read()

with open('VERSION', 'r') as version_fh:
    version = version_fh.read().strip()

setuptools.setup(
        name='gpg-sig-graph',
        version=version,
        author="Max Meinhold",
        author_email="mxmeinhold@gmail.com",
        description="A tool for graphing signatures between gpg keys",
        long_description=long_description,
        long_description_content_type='text/markdown',
        url='https://github.com/mxmeinhold/gpg-sig-graph',
        project_urls={
            'Source': 'https://github.com/mxmeinhold/gpg-sig-graph',
            'Tracker': 'https://github.com/mxmeinhold/gpg-sig-graph/issues',
        },
        license='MIT',
        classifiers=[
            'Development Status :: 3',
            'License :: OSI Approved :: MIT License',
            'Enbironment :: Console',
            'Natural Language :: English',
            'Operating System :: OS Independent',
            'Programming Language :: Python :: 3.9',
        ],
        keywords='gpg graphviz dot',
        packages=setuptools.find_packages(),
        python_requires='>=3.8, <4',
        entry_points={
            'console_scripts': [
                'gpg-sig-graph=gpg_sig_graph:main',
            ],
        },
    )
