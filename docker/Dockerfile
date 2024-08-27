FROM --platform=$TARGETPLATFORM debian:12

# Labels and Credits
LABEL \
    name="test" \
    author="test" \
    description="test"

# Environment Variables
ENV DEBIAN_FRONTEND="noninteractive" \
    DATABASE="postgres"
ENV USERNAME="rengine"

RUN apt update -y && apt install -y      \
    wget                \
    git                 \
    unzip               \
    curl  

RUN addgroup --gid 1000 --system $USERNAME && \
    mkdir -p /home/$USERNAME && \
    adduser --gid 1000 --system --shell /bin/false --disabled-password --uid 1000 --home /home/$USERNAME $USERNAME && \
    chown $USERNAME:$USERNAME /home/$USERNAME && \
    mkdir -p /home/$USERNAME/.local/bin && \
    mkdir -p /home/$USERNAME/tools/.github

ENV TOOLPATH="/home/${USERNAME}/tools"

ENV WORDLISTPATH="/home/${USERNAME}/wordlists"

RUN cd $TOOLPATH/.github && git clone https://github.com/shmilylty/OneForAll.git && cd OneForAll && git reset --hard 9ecfda229199ebf30d9338f4c88cbeb7c40e16c2 && \
    cd $TOOLPATH/.github && git clone https://github.com/FortyNorthSecurity/EyeWitness.git && cd EyeWitness && git reset --hard cb09a842f93109836219b2aa2f9f25c58a34bc8c && \
    cd $TOOLPATH/.github && git clone https://github.com/UnaPibaGeek/ctfr.git && cd ctfr && git reset --hard 6c7fecdc6346c4f5322049e38f415d5bddaa420d && \
    cd $TOOLPATH/.github && git clone https://github.com/Tuhinshubhra/CMSeeK.git && cd CMSeeK && git reset --hard 20f9780d2e682874be959cfd487045c92e3c73f4 && \
    cd $TOOLPATH/.github && git clone https://github.com/GiJ03/Infoga.git && cd Infoga && git reset --hard 6834c6f863c2bdc92cc808934bb293571d1939c1 && \
    cd $TOOLPATH/.github && wget https://github.com/m3n0sd0n4ld/GooFuzz/releases/download/1.2.5/GooFuzz.v.1.2.5.zip && unzip GooFuzz.v.1.2.5.zip && rm GooFuzz.v.1.2.5.zip && mv GooFuzz* GooFuzz && echo "#!/bin/bash\n\nbash $TOOLPATH/.github/GooFuzz/GooFuzz \"\$@\"" > /home/$USERNAME/.local/bin/GooFuzz && chmod +x /home/$USERNAME/.local/bin/GooFuzz && \
    cd $TOOLPATH/.github && git clone https://github.com/1ndianl33t/Gf-Patterns && cd Gf-Patterns && git reset --hard 565382db80f001af288b8d71c525a7ce7f17e80d && mkdir -p /home/$USERNAME/.gf/ && cp -r *.json /home/$USERNAME/.gf/ && \
    cd $TOOLPATH/.github && git clone https://github.com/tomnomnom/gf.git && cd gf && git reset --hard dcd4c361f9f5ba302294ed38b8ce278e8ba69006 && cp -r examples/*.json /home/$USERNAME/.gf/ && \ 
    mkdir -p /home/$USERNAME/.nmap/ && cd /home/$USERNAME/.nmap/ && git clone https://github.com/scipag/vulscan.git && cd vulscan && git reset --hard 2640d62400e9953fb9a33e6033dc59a9dc9606ba && ln -s $TOOLPATH/.github/vulscan /home/$USERNAME/.nmap/vulscan && \
    mkdir -p $WORDLISTPATH && \
    wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O $WORDLISTPATH/dicc.txt && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/fuzz-Bo0oM.txt -O $WORDLISTPATH/fuzz-Bo0oM.txt && \
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O $WORDLISTPATH/deepmagic.com-prefixes-top50000.txt && \
    mkdir -p /home/$USERNAME/nuclei-templates && wget https://raw.githubusercontent.com/NagliNagli/Shockwave-OSS/bd7445cd320a174d3073f0a61867a40849d28436/ssrf.yaml -O /home/$USERNAME/nuclei-templates/ssrf_nagli.yaml && \
    mkdir -p /home/$USERNAME/results
