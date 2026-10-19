// CD en kanda-server: build imagen local + recreate compose.
// Job Jenkins: LINUX-WOL-WAKE-CD — SCM https://github.com/daniquir/linux-wol-wake.git (rama main)
// Trigger: Poll SCM (sin GitHub Actions). No publica secretos del lab en este repo.

pipeline {
  agent any

  options {
    timestamps()
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '20'))
  }

  triggers {
    pollSCM('H/5 * * * *')
  }

  environment {
    IMAGE = 'kanda/linux-wol-wake'
    COMPOSE_DIR = '/docker/composes/linux-wol-wake'
    DATA_DIR = '/docker/volumes-data/linux-wol-wake'
  }

  stages {
    stage('Preflight') {
      steps {
        sh '''
          set -eu
          test -d "$COMPOSE_DIR"
          test -f "$COMPOSE_DIR/docker-compose.yml"
          test -f "$COMPOSE_DIR/up.sh"
          test -f "$DATA_DIR/devices.db"
          test -f "$DATA_DIR/.secret_key"
        '''
      }
    }

    stage('Build image') {
      steps {
        sh '''
          set -eu
          SHORT="$(printf '%s' "${GIT_COMMIT}" | cut -c1-12)"
          docker build -t "${IMAGE}:${SHORT}" -t "${IMAGE}:latest" .
        '''
      }
    }

    stage('Deploy') {
      steps {
        sh '''
          set -eu
          cd "$COMPOSE_DIR"
          # Imagen ya etiquetada :latest en Build; compose usa LINUX_WOL_WAKE_VERSION o latest.
          ./up.sh --force-recreate
          docker image ls "${IMAGE}" | head -5
        '''
      }
    }

    stage('Smoke') {
      steps {
        sh '''
          set -eu
          # network_mode: host → health en el host
          for i in 1 2 3 4 5 6 7 8 9 10; do
            if curl -fsS -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:5055/login" | grep -qE '200|302'; then
              echo ok
              exit 0
            fi
            sleep 2
          done
          echo "smoke_fail" >&2
          docker logs linux-wol-wake --tail 80 || true
          exit 1
        '''
      }
    }
  }
}
